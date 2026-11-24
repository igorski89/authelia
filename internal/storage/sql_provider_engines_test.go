// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
)

// TestEngines runs the queries which only the SQLite unit tests reach elsewhere against PostgreSQL and MySQL. It runs
// when AUTHELIA_TEST_POSTGRES_ADDRESS or AUTHELIA_TEST_MYSQL_ADDRESS (tcp://host:port, user, password and database
// 'authelia') is set, as in the CI job 'Migrations on PostgreSQL and MySQL', and is skipped otherwise.
func TestEngines(t *testing.T) {
	engines := map[string]func(config *schema.Configuration) (Provider, error){
		"AUTHELIA_TEST_POSTGRES_ADDRESS": func(config *schema.Configuration) (Provider, error) {
			return NewPostgreSQLProvider(config, nil)
		},
		"AUTHELIA_TEST_MYSQL_ADDRESS": func(config *schema.Configuration) (Provider, error) {
			return NewMySQLProvider(config, nil)
		},
	}

	ran := false

	for env, newProvider := range engines {
		value := os.Getenv(env)
		if value == "" {
			continue
		}

		ran = true

		t.Run(env, func(t *testing.T) {
			address, err := schema.NewAddress(value)
			require.NoError(t, err)

			sql := schema.StorageSQL{Address: &schema.AddressTCP{Address: *address}, Database: "authelia", Username: "authelia", Password: "authelia", Timeout: 5 * time.Second}

			config := &schema.Configuration{Storage: schema.Storage{EncryptionKey: os.Getenv("AUTHELIA_STORAGE_ENCRYPTION_KEY")}}

			if env == "AUTHELIA_TEST_POSTGRES_ADDRESS" {
				config.Storage.PostgreSQL = &schema.StoragePostgreSQL{StorageSQL: sql, Schema: "public"}
			} else {
				config.Storage.MySQL = &schema.StorageMySQL{StorageSQL: sql}
			}

			provider, err := newProvider(config)
			require.NoError(t, err)
			require.NoError(t, provider.StartupCheck())

			t.Cleanup(func() { _ = provider.Close() })

			testEngineSAMLFlows(t, provider)
			testEngineAuthenticationLogs(t, provider)
			testEngineWebAuthnCredentialImported(t, provider)
			testEngineUserRevocations(t, provider)
			testEngineAuthenticationUserUpdates(t, provider)
		})
	}

	if !ran {
		t.Skip("no PostgreSQL or MySQL address given")
	}
}

func testEngineSAMLFlows(t *testing.T, provider Provider) {
	ctx := context.Background()
	now := time.Now()

	expired := model.SAMLFlow{FlowID: uuid.NewString(), CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute), ServiceProvider: "https://sp.example.com", Form: `{}`}
	require.NoError(t, provider.SaveSAMLFlow(ctx, expired))

	flow := model.SAMLFlow{FlowID: uuid.NewString(), CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), ServiceProvider: "https://sp.example.com", Form: `{"SAMLRequest":["x"]}`}
	require.NoError(t, provider.SaveSAMLFlow(ctx, flow))

	loaded, err := provider.LoadSAMLFlow(ctx, flow.FlowID)
	require.NoError(t, err)
	assert.Equal(t, flow.Form, loaded.Form)
	assert.Equal(t, flow.ServiceProvider, loaded.ServiceProvider)

	// Saving a flow removes the expired ones.
	_, err = provider.LoadSAMLFlow(ctx, expired.FlowID)
	assert.True(t, errors.Is(err, ErrNoSAMLFlow), err)

	consumed, err := provider.ConsumeSAMLFlow(ctx, flow.FlowID)
	require.NoError(t, err)
	assert.Equal(t, flow.FlowID, consumed.FlowID)

	_, err = provider.ConsumeSAMLFlow(ctx, flow.FlowID)
	assert.True(t, errors.Is(err, ErrNoSAMLFlow), err)

	_, err = provider.LoadSAMLFlow(ctx, uuid.NewString())
	assert.True(t, errors.Is(err, ErrNoSAMLFlow), err)
}

func testEngineAuthenticationLogs(t *testing.T, provider Provider) {
	ctx := context.Background()
	username := "events-" + uuid.NewString()[:8]
	start := time.Now().UTC().Truncate(time.Second)

	for i := range 3 {
		require.NoError(t, provider.AppendAuthenticationLog(ctx, model.AuthenticationAttempt{
			Time: start.Add(time.Duration(i) * time.Second), Successful: i != 1, Username: username, Type: "1FA",
			RequestURI: "/api/firstfactor", RequestMethod: "POST",
		}))
	}

	page, err := provider.LoadAuthenticationLogs(ctx, username, 2, 0)
	require.NoError(t, err)
	require.Len(t, page, 2)
	assert.True(t, page[0].Time.After(page[1].Time), "newest first")
	assert.False(t, page[1].Successful)

	page, err = provider.LoadAuthenticationLogs(ctx, username, 2, 1)
	require.NoError(t, err)
	require.Len(t, page, 1)
	assert.Equal(t, username, page[0].Username)

	all, err := provider.LoadAuthenticationLogs(ctx, "", 100, 0)
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(all), 3)
}

func testEngineWebAuthnCredentialImported(t *testing.T, provider Provider) {
	ctx := context.Background()
	kid := model.NewBase64([]byte("engine-" + uuid.NewString())).String()

	imported, err := provider.IsWebAuthnCredentialImported(ctx, kid)
	require.NoError(t, err)
	assert.False(t, imported)

	require.NoError(t, provider.SaveWebAuthnCredentialImported(ctx, kid, "keycloak"))
	assert.Error(t, provider.SaveWebAuthnCredentialImported(ctx, kid, "keycloak"), "the credential ID is unique")

	imported, err = provider.IsWebAuthnCredentialImported(ctx, kid)
	require.NoError(t, err)
	assert.True(t, imported)

	require.NoError(t, provider.DeleteWebAuthnCredentialImported(ctx, kid))

	imported, err = provider.IsWebAuthnCredentialImported(ctx, kid)
	require.NoError(t, err)
	assert.False(t, imported)
}

func testEngineUserRevocations(t *testing.T, provider Provider) {
	ctx := context.Background()
	username := "revoked-" + uuid.NewString()[:8]
	at := time.Now().UTC().Truncate(time.Second)

	require.NoError(t, provider.SaveUserRevocation(ctx, username, "", at.Add(-time.Hour)))
	require.NoError(t, provider.SaveUserRevocation(ctx, username, "", at))
	require.NoError(t, provider.SaveUserRevocation(ctx, username, "", at.Add(-time.Minute)))
	require.NoError(t, provider.SaveUserRevocation(ctx, username, "app", at))

	revocations, err := provider.LoadUserRevocations(ctx, username)
	require.NoError(t, err)
	require.Len(t, revocations, 2, "one mark per user and client, which keeps the later time")

	for _, revocation := range revocations {
		assert.True(t, revocation.RevokedAt.Equal(at), revocation.RevokedAt)
	}
}

// testEngineAuthenticationUserUpdates writes the same values twice in the same second, which MySQL counts as a row
// matched but not affected: the update must not be taken as a concurrent change.
func testEngineAuthenticationUserUpdates(t *testing.T, provider Provider) {
	ctx := context.Background()
	username := "updated-" + uuid.NewString()[:8]

	require.NoError(t, provider.CreateAuthenticationUser(ctx, model.AuthenticationUser{Username: username, Email: username + "@example.com"}))
	require.NoError(t, provider.UpdateAuthenticationUserDisabled(ctx, username, true))
	require.NoError(t, provider.UpdateAuthenticationUserDisabled(ctx, username, true))

	user, err := provider.LoadAuthenticationUser(ctx, username)
	require.NoError(t, err)
	assert.True(t, user.Disabled)
}
