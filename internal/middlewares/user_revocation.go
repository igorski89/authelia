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

// IsUserRevoked returns true if a login of the user at authTime, for a client or for the portal when clientID is empty,
// was revoked since: everything a user is logged in with is revoked by a logout, a disable, or a delete, and the mark
// also refuses a session or grant which a request already running saved after the revocation. The marks are loaded once
// per request when ctx keeps request values.
func IsUserRevoked(ctx context.Context, store storage.Provider, username, clientID string, authTime time.Time) (revoked bool, err error) {
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
		if revocation.Revokes(clientID, authTime) {
			return true, nil
		}
	}

	return false, nil
}
