// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	fjwt "authelia.com/provider/oauth2/token/jwt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/storage"
)

const (
	testAdminClientID = "admin-client"
	testAdminPath     = "/api/admin"
	testAdminAudience = "https://login.example.com:8080/api/admin"
)

func TestAdminWhoAmIGETBearerAuthorization(t *testing.T) {
	testCases := []struct {
		name   string
		setup  func(t *testing.T, mock *mocks.MockAutheliaCtx) (header string)
		status int
		error  string
	}{
		{
			"ShouldPermitClientCredentialsToken",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminRead, testAdminAudience)
			},
			http.StatusOK,
			"",
		},
		{
			"ShouldPermitLowerCaseScheme",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "bearer " + mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminRead, testAdminAudience)
			},
			http.StatusOK,
			"",
		},
		{
			"ShouldPermitMintedClientCredentialsToken",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustMintTestAdminToken(t, mock, true, mock.Clock.Now().Add(time.Hour))
			},
			http.StatusOK,
			"",
		},
		{
			"ShouldRefuseMissingToken",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return ""
			},
			http.StatusUnauthorized,
			"",
		},
		{
			"ShouldRefuseSessionCookieWithoutToken",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				userSession, err := mock.Ctx.GetSession()
				require.NoError(t, err)

				userSession.Username = testUsername
				userSession.AuthenticationMethodRefs.UsernameAndPassword = true
				userSession.AuthenticationMethodRefs.TOTP = true

				require.NoError(t, mock.Ctx.SaveSession(&userSession))

				return ""
			},
			http.StatusUnauthorized,
			"",
		},
		{
			"ShouldRefuseBasicScheme",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Basic YWRtaW4tY2xpZW50OmNsaWVudC1zZWNyZXQ="
			},
			http.StatusUnauthorized,
			"",
		},
		{
			"ShouldRefuseEmptyBearer",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer   "
			},
			http.StatusUnauthorized,
			"",
		},
		{
			"ShouldRefuseUnknownToken",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer authelia_at_not-a-real-token"
			},
			http.StatusUnauthorized,
			"invalid_token",
		},
		{
			"ShouldRefuseExpiredToken",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustMintTestAdminToken(t, mock, true, mock.Clock.Now().Add(-time.Minute))
			},
			http.StatusUnauthorized,
			"invalid_token",
		},
		{
			"ShouldRefuseWriteScopeOnReadRoute",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminWrite, testAdminAudience)
			},
			http.StatusForbidden,
			"insufficient_scope",
		},
		{
			"ShouldRefuseTokenForAnotherAudience",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminRead, "https://app.example.com")
			},
			http.StatusUnauthorized,
			"invalid_token",
		},
		{
			"ShouldRefuseClientWithoutAdminScope",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustGetTestOIDCClientCredentialsToken(t, mock)
			},
			http.StatusForbidden,
			"insufficient_scope",
		},
		{
			"ShouldRefuseTokenFromAnotherIssuer",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				token := mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminRead, testAdminAudience)

				mock.Ctx.Request.Header.Set(fasthttp.HeaderXForwardedHost, "auth.example2.com")

				return "Bearer " + token
			},
			http.StatusUnauthorized,
			"invalid_token",
		},
		{
			"ShouldRefuseTokenIssuedToUser",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				return "Bearer " + mustMintTestAdminToken(t, mock, false, mock.Clock.Now().Add(time.Hour))
			},
			http.StatusForbidden,
			"insufficient_scope",
		},
		{
			"ShouldRefuseClientNoLongerRegisteredWithScope",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				token := mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminRead, testAdminAudience)

				config := mock.Ctx.Configuration.IdentityProviders.OIDC
				config.Clients[0].Scopes = []string{oidc.ScopeAutheliaAdminWrite}

				mock.Ctx.Providers.OpenIDConnect = oidc.NewOpenIDConnectProvider(&mock.Ctx.Configuration, mock.StorageMock, mock.Ctx.Providers.Templates)

				return "Bearer " + token
			},
			http.StatusForbidden,
			"insufficient_scope",
		},
		{
			"ShouldRefuseClientNoLongerRegistered",
			func(t *testing.T, mock *mocks.MockAutheliaCtx) string {
				token := mustGetTestAdminToken(t, mock, oidc.ScopeAutheliaAdminRead, testAdminAudience)

				config := mock.Ctx.Configuration.IdentityProviders.OIDC
				config.Clients = config.Clients[1:]

				mock.Ctx.Providers.OpenIDConnect = oidc.NewOpenIDConnectProvider(&mock.Ctx.Configuration, mock.StorageMock, mock.Ctx.Providers.Templates)

				return "Bearer " + token
			},
			http.StatusUnauthorized,
			"invalid_token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			setUpMockClock(mock)

			config := newTestOIDCConfig(t)
			config.Clients = []schema.IdentityProvidersOpenIDConnectClient{newTestAdminClient(t), newTestOIDCClientCredentialsClient(t)}

			setupTestOIDCProvider(t, mock, config)
			setupTestOIDCSessionStore(t, mock)

			header := tc.setup(t, mock)

			mock.Ctx.Response.Reset()
			mock.Ctx.Request.Header.SetMethod(fasthttp.MethodGet)
			mock.Ctx.Request.SetRequestURI(testAdminPath + "/whoami")

			if header != "" {
				mock.Ctx.Request.Header.Set(fasthttp.HeaderAuthorization, header)
			}

			middlewares.RequireBearerClientCredentials(testAdminPath, oidc.ScopeAutheliaAdminRead)(AdminWhoAmIGET)(mock.Ctx)

			assert.Equal(t, tc.status, mock.Ctx.Response.StatusCode())

			body := map[string]string{}

			require.NoError(t, json.Unmarshal(mock.Ctx.Response.Body(), &body))

			if tc.status == http.StatusOK {
				assert.Equal(t, testAdminClientID, body["client_id"])
				assert.Empty(t, mock.Ctx.Response.Header.Peek(fasthttp.HeaderWWWAuthenticate))

				return
			}

			assert.Equal(t, tc.error, body["error"])
			assert.NotEmpty(t, body["error_description"])

			authenticate := string(mock.Ctx.Response.Header.Peek(fasthttp.HeaderWWWAuthenticate))

			if tc.error == "" {
				assert.Equal(t, "Bearer", authenticate)
			} else {
				assert.Contains(t, authenticate, `error="`+tc.error+`"`)
				assert.Contains(t, authenticate, `scope="`+oidc.ScopeAutheliaAdminRead+`"`)
			}
		})
	}
}

func TestAdminWhoAmIGETWithoutOpenIDConnect(t *testing.T) {
	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	mock.Ctx.Request.Header.Set(fasthttp.HeaderAuthorization, "Bearer authelia_at_token")

	middlewares.RequireBearerClientCredentials(testAdminPath, oidc.ScopeAutheliaAdminRead)(AdminWhoAmIGET)(mock.Ctx)

	assert.Equal(t, http.StatusInternalServerError, mock.Ctx.Response.StatusCode())
	assert.Empty(t, mock.Ctx.Response.Header.Peek(fasthttp.HeaderWWWAuthenticate))
}

func newTestAdminClient(t *testing.T) schema.IdentityProvidersOpenIDConnectClient {
	t.Helper()

	client := newTestOIDCClientCredentialsClient(t)

	client.ID = testAdminClientID
	client.Scopes = []string{oidc.ScopeAutheliaAdminRead, oidc.ScopeAutheliaAdminWrite}
	client.Audience = []string{testAdminAudience, "https://app.example.com"}

	return client
}

func mustGetTestAdminToken(t *testing.T, mock *mocks.MockAutheliaCtx, scope, audience string) (token string) {
	t.Helper()

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
		testOIDCFormParameterGrantType:    []string{oidc.GrantTypeClientCredentials},
		oidc.FormParameterClientID:        []string{testAdminClientID},
		testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
		oidc.FormParameterScope:           []string{scope},
		testOIDCFormParameterAudience:     []string{audience},
	})

	OAuth2TokenPOST(mock.Ctx, rw, r)

	require.Equal(t, http.StatusOK, rw.Code, rw.Body.String())

	token, ok := getTestOAuth2ErrorResponse(t, rw)["access_token"].(string)

	require.True(t, ok)
	require.NotEmpty(t, token)

	return token
}

// mustMintTestAdminToken mints an Access Token for the admin client with the admin read scope and audience granted,
// either as the client itself or on behalf of a user, expiring at the given time. Minting it directly is the only way
// to get a token which the token endpoint or configuration validation would refuse to produce.
func mustMintTestAdminToken(t *testing.T, mock *mocks.MockAutheliaCtx, clientCredentials bool, expires time.Time) (token string) {
	t.Helper()

	client, err := mock.Ctx.Providers.OpenIDConnect.GetRegisteredClient(mock.Ctx, testAdminClientID)
	require.NoError(t, err)

	now := mock.Ctx.Providers.Clock.Now()

	session := &oidc.Session{
		ClientID:          testAdminClientID,
		ClientCredentials: clientCredentials,
		DefaultSession: &openid.DefaultSession{
			Headers: &fjwt.Headers{Extra: map[string]any{}},
			Claims: &fjwt.IDTokenClaims{
				Issuer:                          "https://login.example.com:8080",
				Subject:                         "d5b8a9ae-4c1c-4bdc-9a1b-6f1d2f6c0a52",
				IssuedAt:                        fjwt.NewNumericDate(now),
				AuthenticationMethodsReferences: []string{"pwd", "otp", "mfa"},
				Extra:                           map[string]any{},
			},
			RequestedAt: now,
		},
	}

	if !clientCredentials {
		session.Username = testUsername
	}

	session.SetExpiresAt(oauthelia2.AccessToken, expires)

	requester := &oauthelia2.AccessRequest{
		GrantTypes: oauthelia2.Arguments{oidc.GrantTypeAuthorizationCode},
		Request: oauthelia2.Request{
			ID:                "request-admin-user",
			RequestedAt:       now,
			Client:            client,
			RequestedScope:    oauthelia2.Arguments{oidc.ScopeAutheliaAdminRead},
			GrantedScope:      oauthelia2.Arguments{oidc.ScopeAutheliaAdminRead},
			RequestedAudience: oauthelia2.Arguments{testAdminAudience},
			GrantedAudience:   oauthelia2.Arguments{testAdminAudience},
			Session:           session,
			Form:              url.Values{},
		},
	}

	token, signature, err := mock.Ctx.Providers.OpenIDConnect.Strategy.Core.GenerateAccessToken(mock.Ctx, requester)
	require.NoError(t, err)

	oauthSession, err := model.NewOAuth2SessionFromRequest(signature, requester)
	require.NoError(t, err)

	require.NoError(t, mock.StorageMock.SaveOAuth2Session(mock.Ctx, storage.OAuth2SessionTypeAccessToken, *oauthSession))

	return token
}
