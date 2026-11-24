// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"net"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/utils"
)

// TestValidateOIDCTokenExchangePublicSubjectClient checks a public client may permit a confidential client to exchange
// the access tokens issued to it, which upstream refuses as the public client can't have the token exchange grant type.
func TestValidateOIDCTokenExchangePublicSubjectClient(t *testing.T) {
	validator := schema.NewStructValidator()
	config := &schema.Configuration{
		IdentityProviders: schema.IdentityProviders{
			OIDC: &schema.IdentityProvidersOpenIDConnect{ //nolint:gosec // The HMAC secret is a test value.
				HMACSecret:  "rLABDrx87et5KvRHVUgTm3pezWWd8LMN",
				JSONWebKeys: []schema.JWK{{Key: keyRSA2048, CertificateChain: certRSA2048}},
				Clients: []schema.IdentityProvidersOpenIDConnectClient{
					{
						ID:                           "mcp-login",
						Public:                       true,
						AuthorizationPolicy:          "two_factor",
						RedirectURIs:                 []string{"http://127.0.0.1/callback"},
						Scopes:                       []string{oidc.ScopeOpenID},
						Audience:                     []string{"mcp-gateway"},
						RequestedAudienceMode:        "implicit",
						AccessTokenSignedResponseAlg: oidc.SigningAlgRSAUsingSHA256,
						SubjectTokenClientsSupported: []schema.IdentityProvidersOpenIDConnectClientTokenExchangePolicy{
							{ClientID: "mcp-gateway", RequestedTokenTypes: []string{oidc.TokenTypeAccessToken}},
						},
					},
					{
						ID:                   "mcp-gateway",
						Secret:               tOpenIDConnectPBKDF2ClientSecret,
						AuthorizationPolicy:  "two_factor",
						ConsentMode:          "implicit",
						Scopes:               []string{oidc.ScopeOpenID},
						GrantTypes:           []string{oidc.GrantTypeTokenExchange},
						ImpersonationAllowed: true,
					},
				},
			},
		},
	}

	ValidateIdentityProviders(NewValidateCtx(), config, validator)

	assert.Empty(t, validator.Errors())
	assert.Empty(t, validator.Warnings())

	login, gateway := config.IdentityProviders.OIDC.Clients[0], config.IdentityProviders.OIDC.Clients[1]

	assert.Empty(t, login.SubjectTokenTypesSupported, "the defaults only apply to a client with the token exchange grant type")
	assert.Equal(t, oidc.ClientAuthMethodNone, login.TokenEndpointAuthMethod)
	assert.Equal(t, []string{oidc.TokenTypeAccessToken}, gateway.SubjectTokenTypesSupported)
	assert.Equal(t, []string{oidc.TokenTypeAccessToken}, gateway.RequestTokenTypesSupported)
}

// TestValidateKeysTokenExchangeUnsupported checks the token exchange options of upstream which aren't supported, such as
// those of actor tokens, Transaction Tokens and the 'may_act' claim, are refused rather than ignored.
func TestValidateKeysTokenExchangeUnsupported(t *testing.T) {
	keys := []string{
		"identity_providers.oidc.token_exchange.max_actor_chain_depth",
		"identity_providers.oidc.token_exchange.transaction_tokens.trust_domain",
		"identity_providers.oidc.clients[0].actor_token_types_supported",
		"identity_providers.oidc.clients[0].actor_token_issuers_supported",
		"identity_providers.oidc.clients[0].actor_token_clients_supported",
		"identity_providers.oidc.clients[0].actor_token_without_may_act_allowed",
		"identity_providers.oidc.clients[0].subject_token_issuers_supported",
		"identity_providers.oidc.clients[0].token_exchange_may_act.client_id",
		"identity_providers.oidc.clients[0].token_exchange_refresh_token_allowed",
		"identity_providers.oidc.clients[0].token_exchange_txn_token_replacement",
		"identity_providers.oidc.clients[0].own_access_token_exchange_allowed",
		"identity_providers.oidc.clients[0].own_access_token_exchange_targets_restricted",
	}

	supported := []string{
		"identity_providers.oidc.token_exchange.token_types",
		"identity_providers.oidc.token_exchange.default_requested_token_type",
		"identity_providers.oidc.lifespans.custom.exchange.grants.token_exchange.access_token",
		"identity_providers.oidc.clients[0].subject_token_types_supported",
		"identity_providers.oidc.clients[0].request_token_types_supported",
		"identity_providers.oidc.clients[0].subject_token_clients_supported[0].client_id",
		"identity_providers.oidc.clients[0].subject_token_clients_supported[0].requested_token_types",
		"identity_providers.oidc.clients[0].impersonation_allowed",
	}

	validator := schema.NewStructValidator()

	ValidateKeys(slices.Concat(keys, supported), nil, "AUTHELIA_", validator)

	require.Len(t, validator.Errors(), len(keys))

	for i, key := range keys {
		assert.EqualError(t, validator.Errors()[i], "configuration key not expected: "+key)
	}
}

func TestValidateOIDCClientTokenExchangeExclusions(t *testing.T) {
	testCases := []struct {
		name     string
		grants   []string
		scopes   []string
		expected []string
	}{
		{"ShouldAllowPlainExchange", []string{oidc.GrantTypeTokenExchange}, []string{oidc.ScopeOpenID, oidc.ScopeProfile}, nil},
		{"ShouldIgnoreClientsWithoutExchange", []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken}, []string{oidc.ScopeOfflineAccess}, nil},
		{"ShouldRefuseRefreshGrant", []string{oidc.GrantTypeTokenExchange, oidc.GrantTypeRefreshToken}, []string{oidc.ScopeOpenID}, []string{"option 'grant_types' must not contain 'refresh_token'"}},
		{"ShouldRefuseOfflineAndPrivilegedScopes", []string{oidc.GrantTypeTokenExchange}, []string{oidc.ScopeOfflineAccess, oidc.ScopeAutheliaBearerAuthz, oidc.ScopeAutheliaAdminWrite}, []string{
			"option 'scopes' must not contain 'offline_access'", "option 'scopes' must not contain 'authelia.bearer.authz'", "option 'scopes' must not contain 'authelia.admin.write'",
		}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &schema.IdentityProvidersOpenIDConnect{Clients: []schema.IdentityProvidersOpenIDConnectClient{{ID: "gateway", GrantTypes: tc.grants, Scopes: tc.scopes}}}
			validator := schema.NewStructValidator()

			validateOIDCClientTokenExchangeExclusions(0, config, validator, utils.IsStringInSlice(oidc.GrantTypeTokenExchange, tc.grants))

			require.Len(t, validator.Errors(), len(tc.expected))

			for i, expected := range tc.expected {
				assert.Contains(t, validator.Errors()[i].Error(), expected)
			}
		})
	}
}

func TestValidateOIDCClientTokenExchangeNetworksAndConsent(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")

	config := &schema.IdentityProvidersOpenIDConnect{
		AuthorizationPolicies: map[string]schema.IdentityProvidersOpenIDConnectPolicy{
			"office": {DefaultPolicy: "deny", Rules: []schema.IdentityProvidersOpenIDConnectPolicyRule{{Policy: "one_factor", Networks: []*net.IPNet{network}}}},
		},
		Clients: []schema.IdentityProvidersOpenIDConnectClient{
			{ID: "gateway", GrantTypes: []string{oidc.GrantTypeTokenExchange}, AuthorizationPolicy: "one_factor", Audience: []string{"app"}},
			{ID: "app", AuthorizationPolicy: "office"},
			{ID: "login", ConsentMode: "implicit", SubjectTokenClientsSupported: []schema.IdentityProvidersOpenIDConnectClientTokenExchangePolicy{{ClientID: "gateway"}}},
		},
	}

	validator := schema.NewStructValidator()

	validateOIDCClientTokenExchangeExclusions(0, config, validator, true)
	validateOIDCClientTokenExchangeSubjectConsent(2, config, validator)

	require.Len(t, validator.Errors(), 2)
	assert.Contains(t, validator.Errors()[0].Error(), "option 'authorization_policy' of the client 'app' is 'office', which has rules with 'networks'")
	assert.Contains(t, validator.Errors()[1].Error(), "client 'login': option 'consent_mode' must not be 'implicit' with option 'subject_token_clients_supported'")
}

func TestValidateOIDCClientTokenExchangeTargets(t *testing.T) {
	_, network, _ := net.ParseCIDR("10.0.0.0/8")

	config := &schema.IdentityProvidersOpenIDConnect{
		AuthorizationPolicies: map[string]schema.IdentityProvidersOpenIDConnectPolicy{
			"office": {DefaultPolicy: "deny", Rules: []schema.IdentityProvidersOpenIDConnectPolicyRule{{Policy: "one_factor", Networks: []*net.IPNet{network}}}},
		},
		Clients: []schema.IdentityProvidersOpenIDConnectClient{
			{ID: "gateway", GrantTypes: []string{oidc.GrantTypeTokenExchange}, AuthorizationPolicy: "one_factor",
				Audience: []string{"gateway", "https://cloud.example.com"}, Resource: []string{"office-app"}, AudienceStrategy: "wildcard"},
			{ID: "office-app", AuthorizationPolicy: "office"},
		},
	}

	validator := schema.NewStructValidator()

	validateOIDCClientTokenExchangeExclusions(0, config, validator, true)

	errs := make([]string, 0, len(validator.Errors()))
	for _, err := range validator.Errors() {
		errs = append(errs, err.Error())
	}

	require.Len(t, errs, 3, errs)
	assert.Contains(t, errs[0], "option 'audience_strategy' must be 'exact'")
	assert.Contains(t, errs[1], "must only contain registered client IDs with the token exchange grant type, but they contain 'https://cloud.example.com'")
	assert.Contains(t, errs[2], "option 'authorization_policy' of the client 'office-app' is 'office', which has rules with 'networks'")
}

func TestValidateOIDCClientImplicitAudienceWithResource(t *testing.T) {
	config := &schema.IdentityProvidersOpenIDConnect{
		Clients: []schema.IdentityProvidersOpenIDConnectClient{
			{ID: "without", ImplicitAudienceWithResource: true},
			{ID: "with", ImplicitAudienceWithResource: true, Audience: []string{"gateway"}},
		},
	}

	validator := schema.NewStructValidator()

	validateOIDCClientImplicitAudienceWithResource(0, config, validator)
	validateOIDCClientImplicitAudienceWithResource(1, config, validator)

	require.Len(t, validator.Errors(), 1)
	assert.EqualError(t, validator.Errors()[0], "identity_providers: oidc: clients: client 'without': option 'implicit_audience_with_resource' requires option 'audience'")
}
