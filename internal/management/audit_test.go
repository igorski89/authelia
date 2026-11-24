// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

func TestServiceAudit(t *testing.T) {
	service, store := newTestService(t)

	ctx := WithActor(context.Background(), "client:agent")

	require.NoError(t, service.CreateGroup(ctx, "staff"))

	_, err := service.CreateUser(ctx, NewUser{Username: "john", Email: "john@example.com", Groups: []string{"staff"}, Password: Password{Plain: "a-long-password"}})
	require.NoError(t, err)

	email, disabled := "j@example.com", true

	_, err = service.UpdateUser(ctx, "john", UserChanges{Email: &email, Disabled: &disabled})
	require.NoError(t, err)

	require.NoError(t, service.SetPassword(WithActor(context.Background(), "cli:root"), "john", Password{Plain: "another-long-password"}))
	require.NoError(t, service.RemoveUserFromGroup(ctx, "john", "staff"))
	require.NoError(t, service.DeleteUser(ctx, "john"))

	entries, err := service.ListAudit(ctx, "john", 0, 0)
	require.NoError(t, err)

	actions := make([]string, 0, len(entries))

	for _, entry := range entries {
		actions = append(actions, entry.Action)
	}

	// Newest first. Disabling and deleting both log the user out.
	assert.Equal(t, []string{
		AuditActionUserDelete, AuditActionUserLogout, AuditActionGroupMemberRemove, AuditActionUserPasswordSet,
		AuditActionUserLogout, AuditActionUserDisable, AuditActionUserUpdate, AuditActionUserCreate,
	}, actions)

	byAction := map[string]AuditEntry{}

	for _, entry := range entries {
		byAction[entry.Action] = entry
	}

	assert.Equal(t, "cli:root", byAction[AuditActionUserPasswordSet].Actor)
	assert.Equal(t, "client:agent", byAction[AuditActionUserCreate].Actor)
	assert.Equal(t, map[string]any{"fields": []any{"email"}}, byAction[AuditActionUserUpdate].Details)
	assert.Equal(t, "plain", byAction[AuditActionUserCreate].Details["password"])
	assert.Equal(t, "staff", byAction[AuditActionGroupMemberRemove].Group)
	assert.WithinDuration(t, time.Now(), byAction[AuditActionUserCreate].Time, time.Minute)

	all, err := service.ListAudit(ctx, "", 0, 0)
	require.NoError(t, err)
	assert.Len(t, all, len(entries)+1, "the group creation has no user")

	raw, err := json.Marshal(all)
	require.NoError(t, err)
	assert.NotContains(t, string(raw), "a-long-password")
	assert.NotContains(t, string(raw), "argon2")

	_, err = service.ListAudit(ctx, "", MaxPageSize+1, 0)
	assert.ErrorIs(t, err, ErrInvalid)

	require.NoError(t, store.AppendAuthenticationLog(ctx, model.AuthenticationAttempt{Time: time.Now(), Successful: true, Username: "jane", Type: "1FA", RequestURI: "/api/firstfactor", RequestMethod: "POST"}))

	events, err := service.ListAuthenticationEvents(ctx, "jane", 10, 0)
	require.NoError(t, err)
	require.Len(t, events, 1)
	assert.Equal(t, "1FA", events[0].Type)
	assert.True(t, events[0].Successful)
}

func TestServiceRefusesChangesWithoutActor(t *testing.T) {
	service, _ := newTestService(t)

	ctx := context.Background()

	assert.ErrorIs(t, service.CreateGroup(ctx, "staff"), ErrNoActor)

	groups, err := service.ListGroups(ctx)
	require.NoError(t, err)
	assert.Empty(t, groups, "a change without an actor is rolled back")

	_, err = service.CreateUser(ctx, NewUser{Username: "john", Email: "john@example.com"})
	assert.ErrorIs(t, err, ErrNoActor)

	_, err = service.GetUser(ctx, "john")
	assert.ErrorIs(t, err, ErrNotFound)
}
