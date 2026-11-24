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
	// The upserts keep the later of the existing and the new time, so overlapping revocations never move a mark back
	// and concurrent first marks of a user don't fail on the unique index.
	queryFmtUpsertUserRevocationSQLite = `
		INSERT INTO %s (username, client_id, revoked_at)
		VALUES (?, ?, ?)
			ON CONFLICT (username, client_id)
			DO UPDATE SET revoked_at = MAX(revoked_at, excluded.revoked_at);`

	queryFmtUpsertUserRevocationPostgreSQL = `
		INSERT INTO %[1]s (username, client_id, revoked_at)
		VALUES ($1, $2, $3)
			ON CONFLICT (username, client_id)
			DO UPDATE SET revoked_at = GREATEST(%[1]s.revoked_at, EXCLUDED.revoked_at);`

	queryFmtUpsertUserRevocationMySQL = `
		INSERT INTO %s (username, client_id, revoked_at)
		VALUES (?, ?, ?)
			ON DUPLICATE KEY UPDATE revoked_at = GREATEST(revoked_at, VALUES(revoked_at));`

	queryFmtSelectUserRevocations = `
		SELECT id, username, client_id, revoked_at
		FROM %s
		WHERE username = ?;`
)

// SaveUserRevocation marks the revocation of a user's sessions and tokens, of one client when clientID isn't empty.
// The mark keeps the later time.
func (p *SQLProvider) SaveUserRevocation(ctx context.Context, username, clientID string, revokedAt time.Time) (err error) {
	query := queryFmtUpsertUserRevocationSQLite

	switch p.name {
	case providerPostgres:
		query = queryFmtUpsertUserRevocationPostgreSQL
	case providerMySQL:
		query = queryFmtUpsertUserRevocationMySQL
	}

	if _, err = p.conn(ctx).ExecContext(ctx, fmt.Sprintf(query, tableUserRevocations), username, clientID, revokedAt.UTC()); err != nil {
		return fmt.Errorf("error saving the revocation mark of user '%s': %w", username, err)
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
