// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"fmt"

	"github.com/authelia/authelia/v4/internal/model"
)

const tableAdministrationAudit = "administration_audit"

const (
	queryFmtInsertAdministrationAudit = `
		INSERT INTO %s (time, actor, action, username, group_name, details)
		VALUES (?, ?, ?, ?, ?, ?);`

	queryFmtSelectAdministrationAudit = `
		SELECT id, time, actor, action, username, group_name, details
		FROM %s
		ORDER BY time DESC, id DESC
		LIMIT ?
		OFFSET ?;`

	queryFmtSelectAdministrationAuditByUsername = `
		SELECT id, time, actor, action, username, group_name, details
		FROM %s
		WHERE username = ?
		ORDER BY time DESC, id DESC
		LIMIT ?
		OFFSET ?;`

	queryFmtSelectAuthenticationLogs = `
		SELECT id, time, successful, banned, username, auth_type, remote_ip, request_uri, request_method
		FROM %s
		ORDER BY time DESC, id DESC
		LIMIT ?
		OFFSET ?;`

	queryFmtSelectAuthenticationLogsByUsername = `
		SELECT id, time, successful, banned, username, auth_type, remote_ip, request_uri, request_method
		FROM %s
		WHERE username = ?
		ORDER BY time DESC, id DESC
		LIMIT ?
		OFFSET ?;`
)

// AppendAdministrationAudit records a change made through the administration API or the users and groups commands.
func (p *SQLProvider) AppendAdministrationAudit(ctx context.Context, entry model.AdministrationAuditEntry) (err error) {
	if _, err = p.conn(ctx).ExecContext(ctx, p.db.Rebind(fmt.Sprintf(queryFmtInsertAdministrationAudit, tableAdministrationAudit)),
		entry.Time.UTC(), entry.Actor, entry.Action, entry.Username, entry.Group, entry.Details); err != nil {
		return fmt.Errorf("error inserting administration audit entry '%s': %w", entry.Action, err)
	}

	return nil
}

// LoadAdministrationAudit loads a page of administration audit entries, newest first, of one user when the username
// isn't empty.
func (p *SQLProvider) LoadAdministrationAudit(ctx context.Context, username string, limit, page int) (entries []model.AdministrationAuditEntry, err error) {
	entries = []model.AdministrationAuditEntry{}

	if username == "" {
		err = p.conn(ctx).SelectContext(ctx, &entries, p.db.Rebind(fmt.Sprintf(queryFmtSelectAdministrationAudit, tableAdministrationAudit)), limit, limit*page)
	} else {
		err = p.conn(ctx).SelectContext(ctx, &entries, p.db.Rebind(fmt.Sprintf(queryFmtSelectAdministrationAuditByUsername, tableAdministrationAudit)), model.CanonicalAuthenticationUsername(username), limit, limit*page)
	}

	if err != nil {
		return nil, fmt.Errorf("error selecting administration audit entries: %w", err)
	}

	return entries, nil
}

// LoadAuthenticationLogs loads a page of authentication attempts, newest first, of one user when the username isn't
// empty.
func (p *SQLProvider) LoadAuthenticationLogs(ctx context.Context, username string, limit, page int) (attempts []model.AuthenticationAttempt, err error) {
	attempts = []model.AuthenticationAttempt{}

	if username == "" {
		err = p.conn(ctx).SelectContext(ctx, &attempts, p.db.Rebind(fmt.Sprintf(queryFmtSelectAuthenticationLogs, tableAuthenticationLogs)), limit, limit*page)
	} else {
		err = p.conn(ctx).SelectContext(ctx, &attempts, p.db.Rebind(fmt.Sprintf(queryFmtSelectAuthenticationLogsByUsername, tableAuthenticationLogs)), username, limit, limit*page)
	}

	if err != nil {
		return nil, fmt.Errorf("error selecting authentication logs: %w", err)
	}

	return attempts, nil
}
