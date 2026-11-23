// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"database/sql"
	"time"
)

// SAMLFlow is a SAML authentication request which waits for the user to log in, kept as the form which resumes it at
// the single sign-on endpoint. Login replaces the session of the user, so it is kept in the database, like the consent
// session of an OpenID Connect 1.0 authorization request.
type SAMLFlow struct {
	ID              int          `db:"id"`
	FlowID          string       `db:"flow_id"`
	CreatedAt       time.Time    `db:"created_at"`
	ExpiresAt       time.Time    `db:"expires_at"`
	ServiceProvider string       `db:"service_provider"`
	Form            string       `db:"form"`
	ConsumedAt      sql.NullTime `db:"consumed_at"`
}
