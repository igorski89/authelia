// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
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
