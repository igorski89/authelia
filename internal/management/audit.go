// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/authelia/authelia/v4/internal/model"
)

// Audit actions.
const (
	AuditActionUserCreate         = "user.create"
	AuditActionUserUpdate         = "user.update"
	AuditActionUserDisable        = "user.disable"
	AuditActionUserEnable         = "user.enable"
	AuditActionUserDelete         = "user.delete"
	AuditActionUserPasswordSet    = "user.password.set"
	AuditActionUserPasswordRemove = "user.password.remove"
	AuditActionUserLogout         = "user.logout"
	AuditActionGroupCreate        = "group.create"
	AuditActionGroupDelete        = "group.delete"
	AuditActionGroupMemberAdd     = "group.member.add"
	AuditActionGroupMemberRemove  = "group.member.remove"
)

// ErrNoActor is returned when a change is requested without saying who makes it; see WithActor.
var ErrNoActor = errors.New("the change has no actor to record in the audit")

type ctxKeyActor struct{}

// WithActor returns a context carrying who makes the changes, which is recorded in the audit: for example
// 'client:agent' for an administration API client, or 'cli:root' for the CLI run by the operating system user root.
// Every change requires one.
func WithActor(ctx context.Context, actor string) context.Context {
	return context.WithValue(ctx, ctxKeyActor{}, actor)
}

func actorFrom(ctx context.Context) (actor string, err error) {
	if actor, _ = ctx.Value(ctxKeyActor{}).(string); actor == "" {
		return "", ErrNoActor
	}

	return actor, nil
}

// AuditEntry is one change in the audit, as the administration API and the CLI show it.
type AuditEntry struct {
	ID       int            `json:"id"`
	Time     time.Time      `json:"time"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Username string         `json:"username,omitempty"`
	Group    string         `json:"group,omitempty"`
	Details  map[string]any `json:"details,omitempty"`
}

// AuthenticationEvent is one authentication attempt, as the administration API shows it.
type AuthenticationEvent struct {
	Time          time.Time `json:"time"`
	Username      string    `json:"username"`
	Type          string    `json:"type"`
	Successful    bool      `json:"successful"`
	Banned        bool      `json:"banned"`
	RemoteIP      string    `json:"remote_ip,omitempty"`
	RequestURI    string    `json:"request_uri,omitempty"`
	RequestMethod string    `json:"request_method,omitempty"`
}

// audit records a change in the audit, in the transaction of the change.
func (s *Service) audit(ctx context.Context, action, username, group string, details map[string]any) (err error) {
	var actor string

	if actor, err = actorFrom(ctx); err != nil {
		return err
	}

	entry := model.AdministrationAuditEntry{
		Time:     time.Now().UTC(),
		Actor:    actor,
		Action:   action,
		Username: sql.NullString{String: username, Valid: username != ""},
		Group:    sql.NullString{String: group, Valid: group != ""},
	}

	if len(details) != 0 {
		var data []byte

		if data, err = json.Marshal(details); err != nil {
			return fmt.Errorf("error encoding the audit details: %w", err)
		}

		entry.Details = sql.NullString{String: string(data), Valid: true}
	}

	return s.store.AppendAdministrationAudit(ctx, entry)
}

// ListAudit returns a page of the audit, newest first, of one user when the username isn't empty. A zero limit lists
// DefaultPageSize entries.
func (s *Service) ListAudit(ctx context.Context, username string, limit, page int) (entries []AuditEntry, err error) {
	if limit, err = pageLimit(limit, page); err != nil {
		return nil, err
	}

	var rows []model.AdministrationAuditEntry

	if rows, err = s.store.LoadAdministrationAudit(ctx, username, limit, page); err != nil {
		return nil, err
	}

	entries = make([]AuditEntry, len(rows))

	for i, row := range rows {
		entries[i] = AuditEntry{ID: row.ID, Time: row.Time.UTC(), Actor: row.Actor, Action: row.Action, Username: row.Username.String, Group: row.Group.String}

		if row.Details.Valid {
			_ = json.Unmarshal([]byte(row.Details.String), &entries[i].Details)
		}
	}

	return entries, nil
}

// ListAuthenticationEvents returns a page of authentication attempts, newest first, of one user when the username
// isn't empty. A zero limit lists DefaultPageSize events.
func (s *Service) ListAuthenticationEvents(ctx context.Context, username string, limit, page int) (events []AuthenticationEvent, err error) {
	if limit, err = pageLimit(limit, page); err != nil {
		return nil, err
	}

	var rows []model.AuthenticationAttempt

	if rows, err = s.store.LoadAuthenticationLogs(ctx, username, limit, page); err != nil {
		return nil, err
	}

	events = make([]AuthenticationEvent, len(rows))

	for i, row := range rows {
		events[i] = AuthenticationEvent{Time: row.Time.UTC(), Username: row.Username, Type: row.Type, Successful: row.Successful,
			Banned: row.Banned, RequestURI: row.RequestURI, RequestMethod: row.RequestMethod}

		if row.RemoteIP.IP != nil {
			events[i].RemoteIP = row.RemoteIP.IP.String()
		}
	}

	return events, nil
}

func pageLimit(limit, page int) (int, error) {
	switch {
	case limit == 0:
		limit = DefaultPageSize
	case limit < 0 || limit > MaxPageSize:
		return 0, fmt.Errorf("%w: the limit must be between 1 and %d", ErrInvalid, MaxPageSize)
	}

	if page < 0 {
		return 0, fmt.Errorf("%w: the page must not be negative", ErrInvalid)
	}

	return limit, nil
}
