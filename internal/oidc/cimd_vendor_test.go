// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/configuration/validator"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// A dated snapshot: the Client ID Metadata Documents the AI apps published on 2026-11-25 (opencode 2.4.1, pi 1.6.0), verbatim. It shows which
// of them the resolver accepts as they are, and the client it builds from each. The apps may change their documents.
var vendorClientIDMetadataDocuments = map[string]string{
	"https://claude.ai/oauth/mcp-oauth-client-metadata":   `{"client_id":"https://claude.ai/oauth/mcp-oauth-client-metadata","client_name":"Claude","client_uri":"https://claude.ai","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"token_endpoint_auth_method":"none"}`,
	"https://claude.ai/oauth/claude-code-client-metadata": `{"client_id":"https://claude.ai/oauth/claude-code-client-metadata","client_name":"Claude Code","client_uri":"https://claude.ai","redirect_uris":["http://localhost/callback","http://127.0.0.1/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}`,
	"https://chatgpt.com/oauth/client.json":               `{"client_id":"https://chatgpt.com/oauth/client.json","client_uri":"https://chatgpt.com/","redirect_uris":["https://chatgpt.com/connector_platform_oauth_redirect"],"token_endpoint_auth_method":"private_key_jwt","token_endpoint_auth_methods_supported":["none","private_key_jwt"],"grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:jwt-bearer"],"response_types":["code"],"client_name":"ChatGPT","logo_uri":"https://persistent.oaistatic.com/sonic/misc/openai-logo.png","token_endpoint_auth_signing_alg":"RS256","jwks_uri":"https://chatgpt.com/oauth/jwks.json"}`,
	"https://vscode.dev/oauth/client-metadata.json":       `{"client_name":"Visual Studio Code","logo_uri":"https://code.visualstudio.com/assets/branding/code-stable.png","grant_types":["authorization_code","refresh_token","urn:ietf:params:oauth:grant-type:device_code"],"response_types":["code"],"token_endpoint_auth_method":"none","application_type":"native","client_id":"https://vscode.dev/oauth/client-metadata.json","client_uri":"https://vscode.dev/product","redirect_uris":["http://127.0.0.1:33418/","https://vscode.dev/redirect"]}`,
	"https://opencode.ai/oauth/opencode/client.json":      `{"client_id":"https://opencode.ai/oauth/opencode/client.json","client_name":"opencode","client_uri":"https://opencode.ai","logo_uri":"https://opencode.ai/web-app-manifest-512x512.png","application_type":"native","redirect_uris":["http://127.0.0.1/callback","http://localhost/callback","http://127.0.0.1/mcp/oauth/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","token_endpoint_auth_methods_supported":["none"]}`,
	"https://pi.dev/oauth/client.json":                    `{"client_id":"https://pi.dev/oauth/client.json","client_name":"pi","client_uri":"https://pi.dev","logo_uri":"https://pi.dev/logo.svg","application_type":"native","redirect_uris":["http://127.0.0.1/callback","http://localhost/callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none","token_endpoint_auth_methods_supported":["none"]}`,
}

type vendorDocumentTransport struct{}

func (vendorDocumentTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	body, ok := vendorClientIDMetadataDocuments[r.URL.String()]
	if !ok {
		return &http.Response{StatusCode: http.StatusNotFound, Body: io.NopCloser(strings.NewReader("")), Header: http.Header{}, Request: r}, nil
	}

	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: http.Header{"Content-Type": []string{"application/json"}}, Request: r}, nil
}

func TestClientIDMetadataDocumentsVendorDocuments(t *testing.T) {
	rule := func(domain string, loopback bool) schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule {
		return schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{
			Domain:                       domain,
			AuthorizationPolicy:          "two_factor",
			ConsentMode:                  "explicit",
			Scopes:                       []string{oidc.ScopeOpenID, oidc.ScopeProfile, oidc.ScopeEmail, oidc.ScopeGroups, oidc.ScopeOfflineAccess},
			Audience:                     []string{"gateway"},
			Resource:                     []string{"https://mcp.example.com/mcp"},
			ImplicitAudienceWithResource: true,
			SubjectTokenClientsSupported: []string{"gateway"},
			AllowLoopbackRedirectURIs:    loopback,
		}
	}

	config := &schema.Configuration{
		IdentityProviders: schema.IdentityProviders{
			OIDC: &schema.IdentityProvidersOpenIDConnect{
				IssuerPrivateKey: x509PrivateKeyRSA2048,
				HMACSecret:       strings.Repeat("h", 64),
				TokenExchange: schema.IdentityProvidersOpenIDConnectTokenExchange{
					TokenTypes: []string{oidc.TokenTypeAccessToken},
				},
				Clients: []schema.IdentityProvidersOpenIDConnectClient{
					{
						ID:                      "gateway",
						Secret:                  tOpenIDConnectPBKDF2ClientSecret,
						TokenEndpointAuthMethod: oidc.ClientAuthMethodClientSecretPost,
						GrantTypes:              []string{oidc.GrantTypeTokenExchange},
						ResponseTypes:           []string{},
						RedirectURIs:            []string{},
						AuthorizationPolicy:     "two_factor",
					},
				},
				ClientIDMetadataDocuments: schema.IdentityProvidersOpenIDConnectClientIDMetadataDocuments{
					Enabled: true,
					Rules: []schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{
						rule("claude.ai", true),
						rule("chatgpt.com", false),
						rule("vscode.dev", true),
						rule("opencode.ai", true),
						rule("pi.dev", true),
					},
				},
			},
		},
	}

	val := schema.NewStructValidator()
	validator.ValidateIdentityProviders(validator.NewValidateCtx(), config, val)
	require.Empty(t, val.Errors())

	provider := oidc.NewOpenIDConnectProvider(config, nil, nil)
	require.NotNil(t, provider)
	require.NoError(t, provider.EnableClientIDMetadataDocuments(config, nil, nil))
	require.NotNil(t, provider.ClientIDMetadataDocuments)

	provider.Config.Issuer = "https://id.example.com"
	provider.ClientIDMetadataDocuments.HTTPClient.HTTPClient.Transport = vendorDocumentTransport{}

	// Claude Code's document declares http loopback redirects without the 'native' application_type, which the
	// library refuses for the default 'web' type. The opencode and pi documents are native and also list
	// 'http://localhost/callback', which is dropped as they send 127.0.0.1.
	refused := map[string]string{
		"https://claude.ai/oauth/claude-code-client-metadata": "must use the 'https' scheme.",
	}

	for id := range vendorClientIDMetadataDocuments {
		t.Run(id, func(t *testing.T) {
			client, err := provider.GetResolvedClient(context.Background(), id)

			if reason, ok := refused[id]; ok {
				require.Error(t, err)
				assert.Contains(t, oauthelia2.ErrorToDebugRFC6749Error(err).Error(), reason)

				return
			}

			require.NoError(t, err, oauthelia2.ErrorToDebugRFC6749Error(err))

			c, ok := client.(*oidc.MetadataDocumentClient)
			require.True(t, ok)

			assert.Equal(t, oidc.ClientAuthMethodNone, c.GetTokenEndpointAuthMethod(), "only public clients are built from documents")
			assert.Equal(t, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken}, []string(c.GetGrantTypes()), "other grant types of the document are dropped")
			assert.Equal(t, []string{"gateway"}, c.GetTokenExchangePermittedClientIDs())
			assert.Equal(t, vendorRedirectURIs(t, id), c.GetRedirectURIs())
		})
	}
}

func vendorRedirectURIs(t *testing.T, id string) []string {
	var document struct {
		RedirectURIs []string `json:"redirect_uris"`
	}

	require.NoError(t, json.Unmarshal([]byte(vendorClientIDMetadataDocuments[id]), &document))

	return slices.DeleteFunc(document.RedirectURIs, func(uri string) bool { return strings.HasPrefix(uri, "http://localhost") })
}
