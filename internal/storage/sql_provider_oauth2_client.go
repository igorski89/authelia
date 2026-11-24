// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
)

const queryFmtRevokeOAuth2SessionsByClientID = `
	UPDATE %s
	SET revoked = TRUE
	WHERE client_id = ? AND revoked = FALSE;`

// RevokeOAuth2RefreshTokensByClientID revokes every refresh token issued to the client, such as a client whose Client
// ID Metadata Document now names another client.
func (p *SQLProvider) RevokeOAuth2RefreshTokensByClientID(ctx context.Context, clientID string) (revoked int64, err error) {
	query := p.db.Rebind(fmt.Sprintf(queryFmtRevokeOAuth2SessionsByClientID, tableOAuth2RefreshTokenSession))

	result, err := p.conn(ctx).ExecContext(ctx, query, clientID)
	if err != nil {
		return 0, fmt.Errorf("error revoking the refresh tokens of the client '%s': %w", clientID, err)
	}

	return result.RowsAffected()
}
