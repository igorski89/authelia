// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

const tableWebAuthnCredentialsImported = "webauthn_credentials_imported" //nolint:gosec // This is a table name, not a credential.

//nolint:gosec // These are SQL queries, not credentials.
const (
	queryFmtInsertWebAuthnCredentialImported = `
		INSERT INTO %s (kid, source)
		VALUES (?, ?);`

	queryFmtSelectWebAuthnCredentialImported = `
		SELECT source
		FROM %s
		WHERE kid = ?;`

	queryFmtDeleteWebAuthnCredentialImported = `
		DELETE FROM %s
		WHERE kid = ?;`
)

// SaveWebAuthnCredentialImported marks a WebAuthn credential, by its credential ID, as imported from another system
// which doesn't keep its backup eligible and backup state flags. The first verified sign in adopts them.
func (p *SQLProvider) SaveWebAuthnCredentialImported(ctx context.Context, kid, source string) (err error) {
	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtInsertWebAuthnCredentialImported, tableWebAuthnCredentialsImported)), kid, source); err != nil {
		return fmt.Errorf("error marking WebAuthn credential '%s' as imported: %w", kid, err)
	}

	return nil
}

// IsWebAuthnCredentialImported returns true if a WebAuthn credential is marked as imported with unknown flags.
func (p *SQLProvider) IsWebAuthnCredentialImported(ctx context.Context, kid string) (imported bool, err error) {
	var source string

	if err = p.conn(ctx).GetContext(ctx, &source, p.db.Rebind(fmt.Sprintf(queryFmtSelectWebAuthnCredentialImported, tableWebAuthnCredentialsImported)), kid); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}

		return false, fmt.Errorf("error selecting the import mark of WebAuthn credential '%s': %w", kid, err)
	}

	return true, nil
}

// DeleteWebAuthnCredentialImported removes the import mark of a WebAuthn credential once its flags are known.
func (p *SQLProvider) DeleteWebAuthnCredentialImported(ctx context.Context, kid string) (err error) {
	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtDeleteWebAuthnCredentialImported, tableWebAuthnCredentialsImported)), kid); err != nil {
		return fmt.Errorf("error deleting the import mark of WebAuthn credential '%s': %w", kid, err)
	}

	return nil
}
