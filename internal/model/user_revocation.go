// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"time"
)

// UserRevocation marks when everything a user was logged in with was revoked: its portal sessions and tokens of every
// client when ClientID is empty, otherwise the tokens of that client. A session or grant from a login before RevokedAt
// is refused even if it was saved after the revocation, such as by a request which was already running.
type UserRevocation struct {
	ID        int       `db:"id"`
	Username  string    `db:"username"`
	ClientID  string    `db:"client_id"`
	RevokedAt time.Time `db:"revoked_at"`
}

// Revokes returns true if the mark revokes something which started at the time for the client, which is empty for a
// portal session: a portal session's login, or an OAuth 2.0 grant's authorization request. The resolution is the one of
// the time: a portal session's login time has a resolution of a second, so a login in the same second as the revocation
// is taken as after it; an authorization request's time is exact, so its resolution is zero.
func (r UserRevocation) Revokes(clientID string, at time.Time, resolution time.Duration) bool {
	if r.ClientID != "" && r.ClientID != clientID {
		return false
	}

	return at.Before(r.RevokedAt.Truncate(resolution))
}
