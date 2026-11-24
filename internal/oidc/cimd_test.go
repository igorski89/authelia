// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func newTestClientIDMetadataDocuments(rules ...schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule) *ClientIDMetadataDocuments {
	for i := range rules {
		rules[i].Client = schema.IdentityProvidersOpenIDConnectClient{
			Public:                  true,
			Scopes:                  []string{ScopeOpenID, ScopeProfile, ScopeOfflineAccess},
			GrantTypes:              []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
			ResponseTypes:           []string{ResponseTypeAuthorizationCodeFlow},
			TokenEndpointAuthMethod: ClientAuthMethodNone,
			PKCEChallengeMethod:     PKCEChallengeMethodSHA256,
			AuthorizationPolicy:     "one_factor",
			ConsentMode:             ClientConsentModeExplicit.String(),
		}
	}

	return &ClientIDMetadataDocuments{
		rules:    rules,
		oidc:     &schema.IdentityProvidersOpenIDConnect{},
		policies: map[string]ClientAuthorizationPolicy{"one_factor": {Name: "one_factor"}},
	}
}

func newTestClientIDMetadataDocumentRecord(id string, metadata *oauthelia2.ClientRegistrationMetadata) *oauthelia2.ClientIDMetadataDocumentRecord {
	return &oauthelia2.ClientIDMetadataDocumentRecord{ID: id, Metadata: metadata, FetchedAt: time.Now()}
}

func TestClientIDMetadataDocumentsRule(t *testing.T) {
	documents := newTestClientIDMetadataDocuments(
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai"},
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: ".example.com"},
	)

	testCases := []struct {
		host     string
		expected string
	}{
		{"claude.ai", "claude.ai"},
		{"CLAUDE.AI.", "claude.ai"},
		{"evil.claude.ai", ""},
		{"notclaude.ai", ""},
		{"example.com", ""},
		{"app.example.com", ".example.com"},
		{"a.b.example.com", ".example.com"},
		{"badexample.com", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.host, func(t *testing.T) {
			rule := documents.Rule(tc.host)

			if tc.expected == "" {
				assert.Nil(t, rule)
			} else {
				require.NotNil(t, rule)
				assert.Equal(t, tc.expected, rule.Domain)
			}
		})
	}
}

func TestClientIDMetadataDocumentsNewClient(t *testing.T) {
	documents := newTestClientIDMetadataDocuments(
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai", SubjectTokenClientsSupported: []string{"gateway"}},
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "loopback.example", AllowLoopbackRedirectURIs: true},
	)

	t.Run("ShouldBuildFromRuleAndDocument", func(t *testing.T) {
		client, err := documents.NewClient(context.Background(), newTestClientIDMetadataDocumentRecord("https://claude.ai/client.json", &oauthelia2.ClientRegistrationMetadata{
			ClientName:   "Totally The Bank",
			RedirectURIs: []string{"https://claude.ai/callback"},
			Scope:        "openid profile email admin",
			GrantTypes:   []string{GrantTypeAuthorizationCode},
		}))
		require.NoError(t, err)

		c, ok := client.(*MetadataDocumentClient)
		require.True(t, ok)

		assert.Equal(t, "https://claude.ai/client.json", c.GetID())
		assert.Equal(t, "claude.ai", c.GetName(), "the name is the host, never the document's client_name")
		assert.Equal(t, "claude.ai", c.Host)
		assert.False(t, c.Loopback)
		assert.Equal(t, "web", c.GetApplicationType())
		assert.Equal(t, []string{"https://claude.ai/callback"}, c.GetRedirectURIs())
		assert.Equal(t, oauthelia2.Arguments{ScopeOpenID, ScopeProfile}, c.GetScopes(), "the document narrows the scopes of the rule, never widens them")
		assert.Equal(t, oauthelia2.Arguments{GrantTypeAuthorizationCode}, c.GetGrantTypes())
		assert.True(t, c.IsPublic())
		assert.True(t, c.IsClientIDMetadataDocumentClient())
		assert.Equal(t, []string{"gateway"}, c.GetTokenExchangePermittedClientIDs())
	})

	t.Run("ShouldRefuseLoopbackWithoutRuleOption", func(t *testing.T) {
		_, err := documents.NewClient(context.Background(), newTestClientIDMetadataDocumentRecord("https://claude.ai/cli.json", &oauthelia2.ClientRegistrationMetadata{
			RedirectURIs: []string{"http://127.0.0.1:8080/callback"},
		}))
		assert.ErrorIs(t, err, oauthelia2.ErrInvalidClient)
	})

	t.Run("ShouldRefuseLocalhostWithoutRuleOption", func(t *testing.T) {
		_, err := documents.NewClient(context.Background(), newTestClientIDMetadataDocumentRecord("https://claude.ai/cli.json", &oauthelia2.ClientRegistrationMetadata{
			RedirectURIs: []string{"https://claude.ai/callback", "http://localhost/callback"},
		}))
		assert.ErrorIs(t, err, oauthelia2.ErrInvalidClient)
	})

	t.Run("ShouldAllowLoopbackWithRuleOption", func(t *testing.T) {
		client, err := documents.NewClient(context.Background(), newTestClientIDMetadataDocumentRecord("https://loopback.example/cli.json", &oauthelia2.ClientRegistrationMetadata{
			RedirectURIs: []string{"http://127.0.0.1:8080/callback"},
		}))
		require.NoError(t, err)

		c := client.(*MetadataDocumentClient)
		assert.True(t, c.Loopback)
		assert.Equal(t, "native", c.GetApplicationType())
		assert.Empty(t, c.GetTokenExchangePermittedClientIDs(), "no rule permission means no exchange")
	})

	t.Run("ShouldRefuseHostWithoutRule", func(t *testing.T) {
		_, err := documents.NewClient(context.Background(), newTestClientIDMetadataDocumentRecord("https://evil.claude.ai/client.json", &oauthelia2.ClientRegistrationMetadata{
			RedirectURIs: []string{"https://evil.claude.ai/callback"},
		}))
		assert.ErrorIs(t, err, oauthelia2.ErrInvalidClient)
	})

	t.Run("ShouldNotShareTheRuleClient", func(t *testing.T) {
		_, err := documents.NewClient(context.Background(), newTestClientIDMetadataDocumentRecord("https://claude.ai/a.json", &oauthelia2.ClientRegistrationMetadata{
			RedirectURIs: []string{"https://claude.ai/a"}, Scope: "openid",
		}))
		require.NoError(t, err)

		assert.Equal(t, []string{ScopeOpenID, ScopeProfile, ScopeOfflineAccess}, documents.rules[0].Client.Scopes, "narrowing a client's scopes must not change the rule")
	})
}

func TestClientIDMetadataDocumentCache(t *testing.T) {
	cache := newClientIDMetadataDocumentCache(nil)
	ctx := context.Background()

	_, err := cache.GetClientIDMetadataDocument(ctx, "https://claude.ai/a.json")
	assert.ErrorIs(t, err, oauthelia2.ErrNotFound)

	now := time.Now()

	require.NoError(t, cache.SetClientIDMetadataDocument(ctx, &oauthelia2.ClientIDMetadataDocumentRecord{ID: "https://claude.ai/a.json", Domain: "claude.ai", Metadata: &oauthelia2.ClientRegistrationMetadata{ClientName: "a"}, ExpiresAt: now.Add(time.Hour)}))
	require.NoError(t, cache.SetClientIDMetadataDocument(ctx, &oauthelia2.ClientIDMetadataDocumentRecord{ID: "https://claude.ai/b.json", Domain: "claude.ai", Metadata: &oauthelia2.ClientRegistrationMetadata{}, ExpiresAt: now.Add(-time.Minute)}))

	record, err := cache.GetClientIDMetadataDocument(ctx, "https://claude.ai/a.json")
	require.NoError(t, err)
	assert.Equal(t, "a", record.Metadata.ClientName)

	record.Metadata.ClientName = "changed"

	again, _ := cache.GetClientIDMetadataDocument(ctx, "https://claude.ai/a.json")
	assert.Equal(t, "a", again.Metadata.ClientName, "a record is returned as a copy")

	count, _ := cache.CountClientIDMetadataDocuments(ctx, "claude.ai")
	assert.Equal(t, 2, count)

	require.NoError(t, cache.DeleteExpiredClientIDMetadataDocuments(ctx, now))

	count, _ = cache.CountClientIDMetadataDocuments(ctx, "claude.ai")
	assert.Equal(t, 1, count)

	require.NoError(t, cache.DeleteClientIDMetadataDocument(ctx, "https://claude.ai/a.json"))

	count, _ = cache.CountClientIDMetadataDocuments(ctx, "claude.ai")
	assert.Equal(t, 0, count)
}

func TestClientIDMetadataDocumentsPolicy(t *testing.T) {
	documents := newTestClientIDMetadataDocuments(
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai"},
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "ports.example", Ports: []int{8443}},
	)
	documents.cache = newClientIDMetadataDocumentCache(nil)
	documents.maxPerHost = 2

	testCases := []struct {
		id       string
		expected bool
	}{
		{"https://claude.ai/client.json", true},
		{"https://claude.ai:443/client.json", false},
		{"https://claude.ai:8443/client.json", false},
		{"https://CLAUDE.AI/client.json", false},
		{"https://Claude.ai/client.json", false},
		{"https://claude.ai./client.json", false},
		{"https://evil.claude.ai/client.json", false},
		{"https://ports.example:8443/client.json", true},
		{"https://ports.example/client.json", true},
		{"https://ports.example:9443/client.json", false},
	}

	for _, tc := range testCases {
		t.Run(tc.id, func(t *testing.T) {
			u, err := url.Parse(tc.id)
			require.NoError(t, err)

			err = documents.policy(context.Background(), u)

			if tc.expected {
				assert.NoError(t, err)
			} else {
				assert.ErrorIs(t, err, oauthelia2.ErrInvalidClient)
			}
		})
	}

	t.Run("ShouldCapNewDocumentsPerExactHost", func(t *testing.T) {
		ctx := context.Background()

		for _, id := range []string{"https://claude.ai/a.json", "https://claude.ai/b.json"} {
			require.NoError(t, documents.cache.SetClientIDMetadataDocument(ctx, &oauthelia2.ClientIDMetadataDocumentRecord{ID: id, Domain: "claude.ai", Metadata: &oauthelia2.ClientRegistrationMetadata{}}))
		}

		parse := func(raw string) *url.URL { u, _ := url.Parse(raw); return u }

		assert.ErrorIs(t, documents.policy(ctx, parse("https://claude.ai/c.json")), oauthelia2.ErrInvalidClient, "a new document over the cap of its host")
		assert.NoError(t, documents.policy(ctx, parse("https://claude.ai/a.json")), "a cached document is still served")
		assert.NoError(t, documents.policy(ctx, parse("https://ports.example/a.json")), "another host has its own cap")

		require.NoError(t, documents.cache.SetClientIDMetadataDocument(ctx, &oauthelia2.ClientIDMetadataDocumentRecord{ID: "https://claude.ai/b.json", Domain: "claude.ai", Metadata: &oauthelia2.ClientRegistrationMetadata{}, ExpiresAt: time.Now().Add(-time.Minute)}))

		assert.NoError(t, documents.policy(ctx, parse("https://claude.ai/c.json")), "an expired document doesn't count against the cap")
	})
}
