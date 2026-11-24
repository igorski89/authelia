// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"
	"time"

	"github.com/authelia/authelia/v4/internal/model"
)

const tableUserRevocations = "user_revocations"

const (
	queryFmtDeleteUserRevocation = `
		DELETE FROM %s
		WHERE username = ? AND client_id = ?;`

	queryFmtInsertUserRevocation = `
		INSERT INTO %s (username, client_id, revoked_at)
		VALUES (?, ?, ?);`

	queryFmtSelectUserRevocations = `
		SELECT id, username, client_id, revoked_at
		FROM %s
		WHERE username = ?;`
)

// SaveUserRevocation marks the revocation of a user's sessions and tokens, of one client when clientID isn't empty.
// A later mark replaces an earlier one.
func (p *SQLProvider) SaveUserRevocation(ctx context.Context, username, clientID string, revokedAt time.Time) (err error) {
	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtDeleteUserRevocation, tableUserRevocations)), username, clientID); err != nil {
		return fmt.Errorf("error deleting the revocation mark of user '%s': %w", username, err)
	}

	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtInsertUserRevocation, tableUserRevocations)), username, clientID, revokedAt.UTC()); err != nil {
		return fmt.Errorf("error inserting the revocation mark of user '%s': %w", username, err)
	}

	return nil
}

// LoadUserRevocations loads the revocation marks of a user.
func (p *SQLProvider) LoadUserRevocations(ctx context.Context, username string) (revocations []model.UserRevocation, err error) {
	if err = p.conn(ctx).SelectContext(ctx, &revocations, p.db.Rebind(fmt.Sprintf(queryFmtSelectUserRevocations, tableUserRevocations)), username); err != nil {
		return nil, fmt.Errorf("error selecting the revocation marks of user '%s': %w", username, err)
	}

	return revocations, nil
}
