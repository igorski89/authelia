// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/openid"
	fjwt "authelia.com/provider/oauth2/token/jwt"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/storage"
)

func TestHandleOAuth2TokenUserPermitted(t *testing.T) {
	subject := uuid.MustParse("058606a9-18ed-4dd5-a979-1a647f2ba62f")

	testCases := []struct {
		name     string
		grant    string
		session  *oidc.Session
		setup    func(mock *mocks.MockAutheliaCtx)
		handled  bool
		expected string
	}{
		{
			"ShouldPermitActiveUser",
			oidc.GrantTypeRefreshToken,
			&oidc.Session{DefaultSession: &openid.DefaultSession{Subject: subject.String()}},
			func(mock *mocks.MockAutheliaCtx) {
				mock.StorageMock.EXPECT().LoadUserOpaqueIdentifier(gomock.Any(), subject).Return(&model.UserOpaqueIdentifier{Username: "john"}, nil)
				mock.UserProviderMock.EXPECT().GetDetailsExtended("john").Return(&authentication.UserDetailsExtended{UserDetails: &authentication.UserDetails{Username: "john"}}, nil)
			},
			false,
			"",
		},
		{
			"ShouldRefuseDisabledOrDeletedUser",
			oidc.GrantTypeRefreshToken,
			&oidc.Session{DefaultSession: &openid.DefaultSession{Subject: subject.String()}},
			func(mock *mocks.MockAutheliaCtx) {
				mock.StorageMock.EXPECT().LoadUserOpaqueIdentifier(gomock.Any(), subject).Return(&model.UserOpaqueIdentifier{Username: "john"}, nil)
				mock.UserProviderMock.EXPECT().GetDetailsExtended("john").Return(nil, authentication.ErrUserNotFound)
			},
			true,
			"invalid_grant",
		},
		{
			"ShouldReportTransientErrorAsServerError",
			oidc.GrantTypeAuthorizationCode,
			&oidc.Session{DefaultSession: &openid.DefaultSession{Subject: subject.String()}},
			func(mock *mocks.MockAutheliaCtx) {
				mock.StorageMock.EXPECT().LoadUserOpaqueIdentifier(gomock.Any(), subject).Return(&model.UserOpaqueIdentifier{Username: "john"}, nil)
				mock.UserProviderMock.EXPECT().GetDetailsExtended("john").Return(nil, errors.New("database is locked"))
			},
			true,
			"server_error",
		},
		{
			"ShouldSkipClientCredentials",
			oidc.GrantTypeClientCredentials,
			&oidc.Session{ClientCredentials: true, DefaultSession: &openid.DefaultSession{Subject: "client"}},
			nil,
			false,
			"",
		},
		{
			"ShouldSkipSessionWithoutSubject",
			oidc.GrantTypeRefreshToken,
			&oidc.Session{DefaultSession: &openid.DefaultSession{}},
			nil,
			false,
			"",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			setupTestOIDCProvider(t, mock, nil)

			if tc.setup != nil {
				tc.setup(mock)
			}

			requester := &oauthelia2.AccessRequest{
				GrantTypes: oauthelia2.Arguments{tc.grant},
				Request:    oauthelia2.Request{ID: "request", Client: &oidc.RegisteredClient{ID: "test"}, Session: tc.session},
			}

			rw := httptest.NewRecorder()

			handled := handleOAuth2TokenUserPermitted(mock.Ctx, rw, requester, &oidc.RegisteredClient{ID: "test"}, tc.session)

			assert.Equal(t, tc.handled, handled)

			if tc.handled {
				assert.NotEqual(t, http.StatusOK, rw.Code)
				assert.Contains(t, rw.Body.String(), `"error":"`+tc.expected+`"`)
			}
		})
	}
}

func TestOpenIDConnectUserinfoRefusesUserNoLongerPermitted(t *testing.T) {
	subject := uuid.MustParse("058606a9-18ed-4dd5-a979-1a647f2ba62f")

	mock := mocks.NewMockAutheliaCtx(t)
	defer mock.Close()

	setUpMockClock(mock)

	config := newTestOIDCConfig(t)

	client := newTestOIDCClientCredentialsClient(t)
	client.ID = "user-client"
	client.Scopes = []string{oidc.ScopeOpenID}
	client.GrantTypes = []string{oidc.GrantTypeAuthorizationCode}

	config.Clients = []schema.IdentityProvidersOpenIDConnectClient{client}

	setupTestOIDCProvider(t, mock, config)
	setupTestOIDCSessionStore(t, mock)

	registered, err := mock.Ctx.Providers.OpenIDConnect.GetRegisteredClient(mock.Ctx, "user-client")
	require.NoError(t, err)

	now := mock.Ctx.Providers.Clock.Now()

	session := &oidc.Session{
		ClientID: "user-client",
		DefaultSession: &openid.DefaultSession{
			Headers: &fjwt.Headers{Extra: map[string]any{}},
			Claims: &fjwt.IDTokenClaims{
				Issuer:   "https://login.example.com:8080",
				Subject:  subject.String(),
				IssuedAt: fjwt.NewNumericDate(now),
				Extra:    map[string]any{},
			},
			Subject:     subject.String(),
			RequestedAt: now,
		},
	}

	session.SetExpiresAt(oauthelia2.AccessToken, now.Add(time.Hour))

	requester := &oauthelia2.AccessRequest{
		GrantTypes: oauthelia2.Arguments{oidc.GrantTypeAuthorizationCode},
		Request: oauthelia2.Request{
			ID: "request-user", RequestedAt: now, Client: registered, Session: session, Form: url.Values{},
			RequestedScope: oauthelia2.Arguments{oidc.ScopeOpenID}, GrantedScope: oauthelia2.Arguments{oidc.ScopeOpenID},
		},
	}

	token, signature, err := mock.Ctx.Providers.OpenIDConnect.Strategy.Core.GenerateAccessToken(mock.Ctx, requester)
	require.NoError(t, err)

	oauthSession, err := model.NewOAuth2SessionFromRequest(signature, requester)
	require.NoError(t, err)
	require.NoError(t, mock.StorageMock.SaveOAuth2Session(mock.Ctx, storage.OAuth2SessionTypeAccessToken, *oauthSession))

	mock.StorageMock.EXPECT().LoadUserOpaqueIdentifier(gomock.Any(), subject).Return(&model.UserOpaqueIdentifier{Username: "john"}, nil)
	mock.UserProviderMock.EXPECT().GetDetailsExtended("john").Return(nil, authentication.ErrUserNotFound)

	rw, r := newTestOAuth2Request(t, fasthttp.MethodGet, testOIDCUserinfoEndpoint, nil)

	r.Header.Set(fasthttp.HeaderAuthorization, "Bearer "+token)

	OpenIDConnectUserinfo(mock.Ctx, rw, r)

	assert.Equal(t, http.StatusUnauthorized, rw.Code)
	assert.Contains(t, rw.Body.String(), "no longer permitted to log in")
	assert.NotContains(t, rw.Body.String(), subject.String())
}

func TestHandleOAuth2IntrospectionUserPermitted(t *testing.T) {
	subject := uuid.MustParse("058606a9-18ed-4dd5-a979-1a647f2ba62f")

	newResponse := func(session *oidc.Session) *oauthelia2.IntrospectionResponse {
		return &oauthelia2.IntrospectionResponse{Active: true, AccessRequester: &oauthelia2.AccessRequest{Request: oauthelia2.Request{Session: session}}}
	}

	testCases := []struct {
		name     string
		response *oauthelia2.IntrospectionResponse
		err      error
		active   bool
	}{
		{"ShouldKeepActiveUser", newResponse(&oidc.Session{DefaultSession: &openid.DefaultSession{Subject: subject.String()}}), nil, true},
		{"ShouldDeactivateUserNoLongerPermitted", newResponse(&oidc.Session{DefaultSession: &openid.DefaultSession{Subject: subject.String()}}), authentication.ErrUserNotFound, false},
		{"ShouldKeepActiveOnTransientError", newResponse(&oidc.Session{DefaultSession: &openid.DefaultSession{Subject: subject.String()}}), errors.New("database is locked"), true},
		{"ShouldSkipClientCredentials", newResponse(&oidc.Session{ClientCredentials: true, DefaultSession: &openid.DefaultSession{Subject: "client"}}), nil, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtx(t)
			defer mock.Close()

			setupTestOIDCProvider(t, mock, nil)

			if !tc.response.GetAccessRequester().GetSession().(*oidc.Session).ClientCredentials {
				mock.StorageMock.EXPECT().LoadUserOpaqueIdentifier(gomock.Any(), subject).Return(&model.UserOpaqueIdentifier{Username: "john"}, nil)

				if tc.err != nil {
					mock.UserProviderMock.EXPECT().GetDetailsExtended("john").Return(nil, tc.err)
				} else {
					mock.UserProviderMock.EXPECT().GetDetailsExtended("john").Return(&authentication.UserDetailsExtended{UserDetails: &authentication.UserDetails{Username: "john"}}, nil)
				}
			}

			handleOAuth2IntrospectionUserPermitted(mock.Ctx, uuid.New(), tc.response)

			assert.Equal(t, tc.active, tc.response.IsActive())
		})
	}
}
