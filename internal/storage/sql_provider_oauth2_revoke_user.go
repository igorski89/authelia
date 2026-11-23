// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
)

const (
	// queryFmtRevokeOAuth2SessionsByUsername revokes the rows of an OAuth 2.0 session table whose subject is one of the
	// opaque identifiers of the user. It is formatted with the session table and the opaque identifier table.
	queryFmtRevokeOAuth2SessionsByUsername = `
		UPDATE %s
		SET revoked = TRUE
		WHERE revoked = FALSE AND subject IN (SELECT identifier FROM %s WHERE username = ?);`

	queryFmtRevokeOAuth2SessionsByUsernameAndClientID = `
		UPDATE %s
		SET revoked = TRUE
		WHERE revoked = FALSE AND client_id = ? AND subject IN (SELECT identifier FROM %s WHERE username = ?);`
)

// RevokeOAuth2SessionsByUsername revokes every OAuth 2.0 and OpenID Connect 1.0 session issued on behalf of the user:
// access, refresh, authorization code, device code, PKCE, and OpenID Connect sessions, and pre-configured consent, for
// every subject identifier of the user. When the client identifier isn't empty only the sessions of that client are
// revoked. It returns the number of rows revoked.
func (p *SQLProvider) RevokeOAuth2SessionsByUsername(ctx context.Context, username, clientID string) (revoked int64, err error) {
	tables := []string{
		tableOAuth2AccessTokenSession,
		tableOAuth2RefreshTokenSession,
		tableOAuth2AuthorizeCodeSession,
		tableOAuth2DeviceCodeSession,
		tableOAuth2PKCERequestSession,
		tableOAuth2OpenIDConnectSession,
		tableOAuth2ConsentPreConfiguration,
	}

	err = p.inTransaction(ctx, func(ctx context.Context) (err error) {
		for _, table := range tables {
			var (
				n     int64
				query string
				args  []any
			)

			if clientID == "" {
				query, args = fmt.Sprintf(queryFmtRevokeOAuth2SessionsByUsername, table, tableUserOpaqueIdentifier), []any{username}
			} else {
				query, args = fmt.Sprintf(queryFmtRevokeOAuth2SessionsByUsernameAndClientID, table, tableUserOpaqueIdentifier), []any{clientID, username}
			}

			result, err := p.conn(ctx).ExecContext(ctx, p.db.Rebind(query), args...)
			if err != nil {
				return fmt.Errorf("error revoking the rows of '%s' for user '%s': %w", table, username, err)
			}

			if n, err = result.RowsAffected(); err == nil {
				revoked += n
			}
		}

		return nil
	})

	return revoked, err
}
