// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	fjwt "authelia.com/provider/oauth2/token/jwt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/management"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/storage"
	"github.com/authelia/authelia/v4/internal/templates"
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

func newTestAdminService(t *testing.T) *management.Service {
	t.Helper()

	config := &schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
			Local:         &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")},
		},
	}

	store, err := storage.NewSQLiteProvider(config)
	require.NoError(t, err)
	require.NoError(t, store.StartupCheck())

	t.Cleanup(func() { _ = store.Close() })

	service, err := management.New(&schema.AuthenticationBackendDatabase{Password: schema.DefaultCIPasswordConfig}, store, nil, nil)
	require.NoError(t, err)

	return service
}

func TestAdminUsersAndGroupsHandlers(t *testing.T) {
	service := newTestAdminService(t)

	type step struct {
		name    string
		handler middlewares.RequestHandler
		values  map[string]string
		query   string
		body    string
		ctype   string
		status  int
		contain string
	}

	steps := []step{
		{"ShouldCreateGroup", AdminGroupsPOST(service), nil, "", `{"name":"staff"}`, "", http.StatusCreated, `"name":"staff"`},
		{"ShouldRefuseDuplicateGroup", AdminGroupsPOST(service), nil, "", `{"name":"staff"}`, "", http.StatusConflict, `"error":"conflict"`},
		{"ShouldCreateUser", AdminUsersPOST(service), nil, "", `{"username":"Jane.Doe","email":"jane@example.com","groups":["staff"],"password":"a-long-password"}`, "", http.StatusCreated, `"username":"jane.doe"`},
		{"ShouldCreateUserWithAt", AdminUsersPOST(service), nil, "", `{"username":"ops@example.org","email":"ops@example.org"}`, "", http.StatusCreated, `"has_password":false`},
		{"ShouldNotExposeDigest", AdminUserGET(service), map[string]string{"username": "jane.doe"}, "", "", "", http.StatusOK, `"has_password":true`},
		{"ShouldDecodeEscapedUsername", AdminUserGET(service), map[string]string{"username": "ops%40example.org"}, "", "", "", http.StatusOK, `"username":"ops@example.org"`},
		{"ShouldRefuseUnknownField", AdminUserPATCH(service), map[string]string{"username": "jane.doe"}, "", `{"displayname":"x"}`, "", http.StatusBadRequest, `unknown field`},
		{"ShouldRefuseWrongContentType", AdminUserPATCH(service), map[string]string{"username": "jane.doe"}, "", `{"display_name":"x"}`, "text/plain", http.StatusBadRequest, `content type`},
		{"ShouldAcceptContentTypeWithCharset", AdminUserPATCH(service), map[string]string{"username": "jane.doe"}, "", `{"display_name":"Jane","disabled":true}`, "application/json; charset=utf-8", http.StatusOK, `"disabled":true`},
		{"ShouldRefuseEmptyPassword", AdminUserPasswordPUT(service), map[string]string{"username": "jane.doe"}, "", `{}`, "", http.StatusBadRequest, `use DELETE`},
		{"ShouldRefusePlaintextDigest", AdminUserPasswordPUT(service), map[string]string{"username": "ops@example.org"}, "", `{"password_digest":"$plaintext$password"}`, "", http.StatusBadRequest, `not a stored password`},
		{"ShouldSetPasswordDigest", AdminUserPasswordPUT(service), map[string]string{"username": "ops@example.org"}, "", `{"password_digest":"$argon2id$v=19$m=64,t=1,p=1$2eqfZS5ZCxmK+sWyv5rauw$qsDFAfTl8ByCIrMMzbU6o1IVe8Ea23YCGph3rqWeIw4"}`, "", http.StatusNoContent, ``},
		{"ShouldRemovePassword", AdminUserPasswordDELETE(service), map[string]string{"username": "jane.doe"}, "", "", "", http.StatusNoContent, ``},
		{"ShouldAddToGroup", AdminUserGroupPUT(service), map[string]string{"username": "ops@example.org", "group": "staff"}, "", "", "", http.StatusNoContent, ``},
		{"ShouldRefuseMissingGroup", AdminUserGroupPUT(service), map[string]string{"username": "ops@example.org", "group": "missing"}, "", "", "", http.StatusNotFound, `"error":"not_found"`},
		{"ShouldListMembers", AdminGroupMembersGET(service), map[string]string{"group": "staff"}, "", "", "", http.StatusOK, `"members":[{"username":"jane.doe"`},
		{"ShouldRemoveFromGroup", AdminUserGroupDELETE(service), map[string]string{"username": "ops@example.org", "group": "staff"}, "", "", "", http.StatusNoContent, ``},
		{"ShouldListUsers", AdminUsersGET(service), nil, "limit=1&page=1", "", "", http.StatusOK, `"users":[{"username":"ops@example.org"`},
		{"ShouldRefuseBadLimit", AdminUsersGET(service), nil, "limit=abc", "", "", http.StatusBadRequest, `must be an integer`},
		{"ShouldListGroups", AdminGroupsGET(service), nil, "", "", "", http.StatusOK, `"name":"staff"`},
		{"ShouldDeleteUser", AdminUserDELETE(service), map[string]string{"username": "jane.doe"}, "", "", "", http.StatusNoContent, ``},
		{"ShouldNotFindDeletedUser", AdminUserGET(service), map[string]string{"username": "jane.doe"}, "", "", "", http.StatusNotFound, `"error":"not_found"`},
		{"ShouldRefuseDeletedUsername", AdminUsersPOST(service), nil, "", `{"username":"jane.doe","email":"jane2@example.com"}`, "", http.StatusConflict, `deleted user`},
		{"ShouldDeleteGroup", AdminGroupDELETE(service), map[string]string{"group": "staff"}, "", "", "", http.StatusNoContent, ``},
		{"ShouldWhoAmI", AdminWhoAmIGET, nil, "", "", "", http.StatusOK, `"client_id":""`},
	}

	for _, st := range steps {
		t.Run(st.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			// The handlers pass the request context to a real database here, which needs the context of a server.
			mock.Ctx.Init(&fasthttp.Request{}, nil, nil)

			for k, v := range st.values {
				mock.Ctx.SetUserValue(k, v)
			}

			mock.Ctx.Request.URI().SetQueryString(st.query)

			if st.body != "" {
				ctype := st.ctype
				if ctype == "" {
					ctype = "application/json"
				}

				mock.Ctx.Request.Header.SetContentType(ctype)
				mock.Ctx.Request.SetBodyString(st.body)
			}

			st.handler(mock.Ctx)

			assert.Equal(t, st.status, mock.Ctx.Response.StatusCode(), string(mock.Ctx.Response.Body()))
			assert.Contains(t, string(mock.Ctx.Response.Body()), st.contain)
			assert.NotContains(t, string(mock.Ctx.Response.Body()), "$argon2")
			assert.NotContains(t, string(mock.Ctx.Response.Body()), "qsDFAfTl8ByCIrMMzbU6o1IVe8Ea23YCGph3rqWeIw4")
		})
	}
}

func TestAdminHandlersReportServerErrorsWithoutDetails(t *testing.T) {
	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	service, err := management.New(&schema.AuthenticationBackendDatabase{Password: schema.DefaultCIPasswordConfig}, mock.StorageMock, nil, nil)
	require.NoError(t, err)

	mock.StorageMock.EXPECT().LoadAuthenticationGroups(gomock.Any()).Return(nil, errors.New("connection refused to 10.0.0.1"))

	AdminGroupsGET(service)(mock.Ctx)

	assert.Equal(t, http.StatusInternalServerError, mock.Ctx.Response.StatusCode())
	assert.NotContains(t, string(mock.Ctx.Response.Body()), "10.0.0.1")
	assert.Contains(t, string(mock.Ctx.Response.Body()), `"error":"server_error"`)
}

func TestAdminUserInvitePOST(t *testing.T) {
	service := newTestAdminService(t)

	ctx := management.WithActor(context.Background(), "test")

	_, err := service.CreateUser(ctx, management.NewUser{Username: "john", Email: "john@example.com", DisplayName: "John"})
	require.NoError(t, err)

	newMock := func(t *testing.T) *mocks.MockAutheliaCtx {
		mock := mocks.NewMockAutheliaCtx(t)
		mock.Ctx.Init(&fasthttp.Request{}, nil, nil)
		mock.Ctx.Request.Header.Set(fasthttp.HeaderXForwardedProto, "https")
		mock.Ctx.Request.Header.Set(fasthttp.HeaderXForwardedHost, "login.example.com:8080")
		mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTSecret = "abc123abc123abc123abc123abc123abc123"
		mock.Ctx.SetUserValue("username", "john")

		return mock
	}

	t.Run("ShouldSendTheLinkByMailOnly", func(t *testing.T) {
		mock := newMock(t)
		defer mock.Close()

		var sent templates.EmailAccountSetupValues

		mock.NotifierMock.EXPECT().Send(gomock.Any(), gomock.Any(), "Set up your account", gomock.Any(), gomock.Any()).
			DoAndReturn(func(_ context.Context, _ mail.Address, _ string, _ *templates.EmailTemplate, data any) error {
				sent = data.(templates.EmailAccountSetupValues)

				return nil
			})

		mock.Ctx.Request.Header.SetContentType("application/json")
		mock.Ctx.Request.SetBodyString(`{"lifespan":"3d"}`)

		AdminUserInvitePOST(service)(mock.Ctx)

		assert.Equal(t, http.StatusAccepted, mock.Ctx.Response.StatusCode(), string(mock.Ctx.Response.Body()))
		assert.Contains(t, sent.LinkURL, "https://login.example.com:8080/account-setup?token=")
		assert.NotContains(t, string(mock.Ctx.Response.Body()), "token")
		assert.Contains(t, string(mock.Ctx.Response.Body()), `"expires_at"`)
	})

	t.Run("ShouldRevokeTheLinkWhenTheMailFails", func(t *testing.T) {
		mock := newMock(t)
		defer mock.Close()

		mock.NotifierMock.EXPECT().Send(gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any(), gomock.Any()).Return(errors.New("smtp down"))

		AdminUserInvitePOST(service)(mock.Ctx)

		assert.Equal(t, http.StatusInternalServerError, mock.Ctx.Response.StatusCode())

		entries, err := service.ListAudit(ctx, "john", 1, 0)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(t, management.AuditActionUserInvite, entries[0].Action)
	})

	t.Run("ShouldRefuseBadLifespan", func(t *testing.T) {
		mock := newMock(t)
		defer mock.Close()

		mock.Ctx.Request.Header.SetContentType("application/json")
		mock.Ctx.Request.SetBodyString(`{"lifespan":"soon"}`)

		AdminUserInvitePOST(service)(mock.Ctx)

		assert.Equal(t, http.StatusBadRequest, mock.Ctx.Response.StatusCode())
	})

	t.Run("ShouldRequireTheSigningSecret", func(t *testing.T) {
		mock := newMock(t)
		defer mock.Close()

		mock.Ctx.Configuration.IdentityValidation.ResetPassword.JWTSecret = ""

		AdminUserInvitePOST(service)(mock.Ctx)

		assert.Equal(t, http.StatusInternalServerError, mock.Ctx.Response.StatusCode())
	})
}

func TestAccountSetupPOSTRequiresRedeemedLink(t *testing.T) {
	service := newTestAdminService(t)

	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	mock.Ctx.Request.SetBodyString(`{"password":"a-long-password"}`)

	AccountSetupPOST(service)(mock.Ctx)

	assert.Contains(t, string(mock.Ctx.Response.Body()), `"status":"KO"`)
}
