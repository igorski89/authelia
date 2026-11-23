// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/model"
)

func TestSQLProviderRevokeOAuth2SessionsByUsername(t *testing.T) {
	provider := newTestSQLiteProvider(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	subjects := map[string]uuid.UUID{"john": uuid.New(), "john-pairwise": uuid.New(), "jane": uuid.New()}

	require.NoError(t, provider.SaveUserOpaqueIdentifier(ctx, model.UserOpaqueIdentifier{Service: "openid", Username: "john", Identifier: subjects["john"]}))
	require.NoError(t, provider.SaveUserOpaqueIdentifier(ctx, model.UserOpaqueIdentifier{Service: "openid", SectorID: "sector.example.com", Username: "john", Identifier: subjects["john-pairwise"]}))
	require.NoError(t, provider.SaveUserOpaqueIdentifier(ctx, model.UserOpaqueIdentifier{Service: "openid", Username: "jane", Identifier: subjects["jane"]}))

	save := func(sessionType OAuth2SessionType, signature, client string, subject uuid.UUID) {
		require.NoError(t, provider.SaveOAuth2Session(ctx, sessionType, model.OAuth2Session{
			ChallengeID: uuid.NullUUID{UUID: uuid.New(), Valid: true}, RequestID: signature, ClientID: client, Signature: signature, RequestedAt: time.Now(),
			Subject: sql.NullString{String: subject.String(), Valid: true}, Active: true, Session: []byte("{}"),
		}))
	}

	save(OAuth2SessionTypeAccessToken, "at-john-app", "app", subjects["john"])
	save(OAuth2SessionTypeRefreshToken, "rt-john-app", "app", subjects["john"])
	save(OAuth2SessionTypeAccessToken, "at-john-other", "other", subjects["john-pairwise"])
	save(OAuth2SessionTypeOpenIDConnect, "oidc-john-other", "other", subjects["john-pairwise"])
	save(OAuth2SessionTypeAccessToken, "at-jane-app", "app", subjects["jane"])

	// A revoked session is no longer loaded at all, which is what makes its token stop working.
	revoked := func(sessionType OAuth2SessionType, signature string) bool {
		session, err := provider.LoadOAuth2Session(ctx, sessionType, signature)
		if errors.Is(err, sql.ErrNoRows) {
			return true
		}

		require.NoError(t, err)

		return session.Revoked
	}

	n, err := provider.RevokeOAuth2SessionsByUsername(ctx, "john", "app")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n)
	assert.True(t, revoked(OAuth2SessionTypeAccessToken, "at-john-app"))
	assert.True(t, revoked(OAuth2SessionTypeRefreshToken, "rt-john-app"))
	assert.False(t, revoked(OAuth2SessionTypeAccessToken, "at-john-other"), "only the given client is revoked")

	n, err = provider.RevokeOAuth2SessionsByUsername(ctx, "john", "")
	require.NoError(t, err)
	assert.Equal(t, int64(2), n, "pairwise subjects are revoked too, already revoked rows are not counted again")
	assert.True(t, revoked(OAuth2SessionTypeAccessToken, "at-john-other"))
	assert.True(t, revoked(OAuth2SessionTypeOpenIDConnect, "oidc-john-other"))

	assert.False(t, revoked(OAuth2SessionTypeAccessToken, "at-jane-app"), "other users are not touched")

	n, err = provider.RevokeOAuth2SessionsByUsername(ctx, "nobody", "")
	require.NoError(t, err)
	assert.Equal(t, int64(0), n)
}

func TestSQLProviderRevokePendingIdentityVerificationsByUsername(t *testing.T) {
	provider := newTestSQLiteProvider(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	save := func(username, action string) uuid.UUID {
		jti := uuid.New()

		require.NoError(t, provider.SaveIdentityVerification(ctx, model.NewIdentityVerification(jti, username, action, net.ParseIP("127.0.0.1"), time.Hour)))

		return jti
	}

	invite, reset, other := save("john", "account_setup"), save("john", "reset_password"), save("jane", "account_setup")
	consumed := save("john", "account_setup")

	require.NoError(t, provider.ConsumeIdentityVerification(ctx, consumed.String(), model.NullIP{}))

	// A revoked link is reported with an error rather than as not found.
	found := func(jti uuid.UUID) bool {
		ok, err := provider.FindIdentityVerification(ctx, jti.String())
		if err != nil {
			require.EqualError(t, err, "the token has been revoked")

			return false
		}

		return ok
	}

	n, err := provider.RevokePendingIdentityVerificationsByUsername(ctx, "john", "account_setup")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n, "only the pending link of the action")
	assert.False(t, found(invite))
	assert.True(t, found(reset))

	n, err = provider.RevokePendingIdentityVerificationsByUsername(ctx, "john", "")
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)
	assert.False(t, found(reset))
	assert.True(t, found(other), "other users are not touched")
}
