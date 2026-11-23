// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/authelia/authelia/v4/internal/model"
)

const tableSAMLFlows = "saml_flows"

const (
	queryFmtInsertSAMLFlow = `
		INSERT INTO %s (flow_id, created_at, expires_at, service_provider, form)
		VALUES (?, ?, ?, ?, ?);`

	queryFmtSelectSAMLFlow = `
		SELECT id, flow_id, created_at, expires_at, service_provider, form, consumed_at
		FROM %s
		WHERE flow_id = ?;`

	queryFmtConsumeSAMLFlow = `
		UPDATE %s
		SET consumed_at = ?
		WHERE flow_id = ? AND consumed_at IS NULL;`

	queryFmtDeleteExpiredSAMLFlows = `
		DELETE FROM %s
		WHERE expires_at < ?;`
)

// ErrNoSAMLFlow is returned when a SAML flow does not exist, was already used, or expired.
var ErrNoSAMLFlow = errors.New("no SAML flow found")

// SaveSAMLFlow saves a SAML flow, and removes the flows which expired.
func (p *SQLProvider) SaveSAMLFlow(ctx context.Context, flow model.SAMLFlow) (err error) {
	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtDeleteExpiredSAMLFlows, tableSAMLFlows)), time.Now().UTC()); err != nil {
		return fmt.Errorf("error deleting expired SAML flows: %w", err)
	}

	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtInsertSAMLFlow, tableSAMLFlows)),
		flow.FlowID, flow.CreatedAt.UTC(), flow.ExpiresAt.UTC(), flow.ServiceProvider, flow.Form); err != nil {
		return fmt.Errorf("error inserting SAML flow '%s': %w", flow.FlowID, err)
	}

	return nil
}

// LoadSAMLFlow loads a SAML flow which was neither used nor expired, without using it.
func (p *SQLProvider) LoadSAMLFlow(ctx context.Context, flowID string) (flow *model.SAMLFlow, err error) {
	flow = &model.SAMLFlow{}

	if err = p.conn(ctx).GetContext(ctx, flow, p.db.Rebind(fmt.Sprintf(queryFmtSelectSAMLFlow, tableSAMLFlows)), flowID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoSAMLFlow
		}

		return nil, fmt.Errorf("error selecting SAML flow '%s': %w", flowID, err)
	}

	// Compared in Go, as the engines return the times in different zones.
	if flow.ConsumedAt.Valid || !time.Now().Before(flow.ExpiresAt) {
		return nil, ErrNoSAMLFlow
	}

	return flow, nil
}

// ConsumeSAMLFlow uses a SAML flow which was neither used nor expired and returns it. A flow can be used once.
func (p *SQLProvider) ConsumeSAMLFlow(ctx context.Context, flowID string) (flow *model.SAMLFlow, err error) {
	if flow, err = p.LoadSAMLFlow(ctx, flowID); err != nil {
		return nil, err
	}

	result, err := p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtConsumeSAMLFlow, tableSAMLFlows)), time.Now().UTC(), flowID)
	if err != nil {
		return nil, fmt.Errorf("error consuming SAML flow '%s': %w", flowID, err)
	}

	// Only the one request which marks it as used gets it, also when two arrive at the same time.
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return nil, ErrNoSAMLFlow
	}

	return flow, nil
}
