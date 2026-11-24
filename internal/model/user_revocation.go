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
// portal session: a portal session's login, or an OAuth 2.0 grant's authorization request. The login times have a
// resolution of a second, so a time in the same second as the revocation is taken as after it.
func (r UserRevocation) Revokes(clientID string, authTime time.Time) bool {
	if r.ClientID != "" && r.ClientID != clientID {
		return false
	}

	return authTime.Before(r.RevokedAt.Truncate(time.Second))
}
