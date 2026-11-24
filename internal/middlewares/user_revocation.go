// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"context"
	"time"

	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

// userRevocationsKey is the key of the revocation marks of a user, loaded once per request.
type userRevocationsKey struct {
	username string
}

// requestValues is a context which keeps values for the request, such as *fasthttp.RequestCtx.
type requestValues interface {
	UserValue(key any) any
	SetUserValue(key any, value any)
}

// IsUserRevoked returns true if something of the user which started at the time, with the resolution of that time (see
// model.UserRevocation.Revokes), for a client or for the portal when clientID is empty, was revoked since: everything a user is logged in with is revoked by a logout, a disable, or a delete, and the mark
// also refuses a session or grant which a request already running saved after the revocation. The marks are loaded once
// per request when ctx keeps request values.
func IsUserRevoked(ctx context.Context, store storage.Provider, username, clientID string, at time.Time, resolution time.Duration) (revoked bool, err error) {
	if store == nil || username == "" {
		return false, nil
	}

	var revocations []model.UserRevocation

	values, cached := ctx.(requestValues)

	if cached {
		revocations, cached = values.UserValue(userRevocationsKey{username}).([]model.UserRevocation)
	}

	if !cached {
		if revocations, err = store.LoadUserRevocations(ctx, username); err != nil {
			return false, err
		}

		if values, ok := ctx.(requestValues); ok {
			if revocations == nil {
				revocations = []model.UserRevocation{}
			}

			values.SetUserValue(userRevocationsKey{username}, revocations)
		}
	}

	for _, revocation := range revocations {
		if revocation.Revokes(clientID, at, resolution) {
			return true, nil
		}
	}

	return false, nil
}

// Resolutions of the times compared with the revocation marks.
const (
	// RevocationResolutionLogin is the resolution of the login time of a portal session.
	RevocationResolutionLogin = time.Second

	// RevocationResolutionGrant is the resolution of the time of an OAuth 2.0 authorization request, which is exact.
	RevocationResolutionGrant time.Duration = 0
)
