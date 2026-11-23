// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestServiceCreateInvite(t *testing.T) {
	service, store := newTestService(t)

	ctx := WithActor(context.Background(), "client:agent")
	ip := net.ParseIP("192.0.2.1")

	_, err := service.CreateUser(ctx, NewUser{Username: "john", Email: "john@example.com"})
	require.NoError(t, err)

	first, err := service.CreateInvite(ctx, "JOHN", 0, ip)
	require.NoError(t, err)
	assert.Equal(t, "john", first.User.Username)
	assert.Equal(t, ActionAccountSetup, first.Verification.Action)
	assert.WithinDuration(t, time.Now().Add(DefaultInviteLifespan), first.Verification.ExpiresAt, time.Minute)

	found, err := store.FindIdentityVerification(ctx, first.Verification.JTI.String())
	require.NoError(t, err)
	assert.True(t, found)

	second, err := service.CreateInvite(ctx, "john", time.Hour, ip)
	require.NoError(t, err)

	_, err = store.FindIdentityVerification(ctx, first.Verification.JTI.String())
	assert.EqualError(t, err, "the token has been revoked", "a new invite revokes the earlier one")

	require.NoError(t, service.RevokeInvite(ctx, second))

	_, err = store.FindIdentityVerification(ctx, second.Verification.JTI.String())
	assert.EqualError(t, err, "the token has been revoked")

	_, err = service.CreateInvite(ctx, "john", MaxInviteLifespan+time.Hour, ip)
	assert.ErrorIs(t, err, ErrInvalid)

	_, err = service.CreateInvite(ctx, "john", time.Millisecond, ip)
	assert.ErrorIs(t, err, ErrInvalid)

	_, err = service.CreateInvite(ctx, "nobody", 0, ip)
	assert.ErrorIs(t, err, ErrNotFound)

	disabled := true

	_, err = service.UpdateUser(ctx, "john", UserChanges{Disabled: &disabled})
	require.NoError(t, err)

	_, err = service.CreateInvite(ctx, "john", 0, ip)
	assert.ErrorIs(t, err, ErrInvalid)

	require.NoError(t, service.AuditAccountSetup(context.Background(), "john"))

	entries, err := service.ListAudit(ctx, "john", 0, 0)
	require.NoError(t, err)
	require.NotEmpty(t, entries)
	assert.Equal(t, AuditActionUserSetup, entries[0].Action)
	assert.Equal(t, "user:john", entries[0].Actor)
}
