// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
)

const (
	testOIDCTokenExchangeID = "token-exchange"
	testOIDCActorID         = "actor"
)

//nolint:gosec // These are form parameter names, not credentials.
const (
	testOIDCFormParameterSubjectToken       = "subject_token"
	testOIDCFormParameterSubjectTokenType   = "subject_token_type"
	testOIDCFormParameterRequestedTokenType = "requested_token_type"
	testOIDCFormParameterIssuedTokenType    = "issued_token_type"
	testOIDCFormParameterActorToken         = "actor_token"
	testOIDCFormParameterActorTokenType     = "actor_token_type"
	testOIDCFormParameterRefreshToken       = "refresh_token"
)

// testOIDCTokenExchangeMutator adjusts the provider and client configurations of a Token Exchange test before the
// provider is created.
type testOIDCTokenExchangeMutator func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient)

// TestOAuth2TokenPOSTTokenExchange drives a real RFC 8693 Token Exchange through the provider: the subject token is
// obtained via the Authorization Code Flow as one client, then exchanged by a second client.
func TestOAuth2TokenPOSTTokenExchange(t *testing.T) {
	impersonationMutator := func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
		exchange.ImpersonationAllowed = true
	}

	t.Run("ShouldAttributeExchangedJWTProfileAccessTokenToRequestingClient", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			config.Discovery.JWTResponseAccessTokens = true

			exchange.AccessTokenSignedResponseAlg = oidc.SigningAlgRSAUsingSHA256
			exchange.AccessTokenSignedResponseKeyID = testOIDCKeyID
			exchange.ImpersonationAllowed = true
		})

		subject := mustGetTestOIDCSubjectAccessToken(t, mock)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{subject},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		response := getTestOAuth2ErrorResponse(t, rw)

		require.Equal(t, http.StatusOK, rw.Code, response)

		token, ok := response["access_token"].(string)

		require.True(t, ok)

		claims := mustDecodeTestJWTClaims(t, token)

		assert.Equal(t, testOIDCTokenExchangeID, claims[oidc.ClaimClientIdentifier], "the 'client_id' claim must identify the client which requested the exchange")
	})

	t.Run("ShouldExchangeAccessTokenForUsableAccessToken", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator)

		subject := mustGetTestOIDCSubjectAccessToken(t, mock)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{subject},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		response := getTestOAuth2ErrorResponse(t, rw)

		require.Equal(t, http.StatusOK, rw.Code, response)

		assert.Equal(t, oidc.TokenTypeAccessToken, response[testOIDCFormParameterIssuedTokenType])
		assert.Equal(t, "bearer", response["token_type"])

		token, ok := response["access_token"].(string)

		require.True(t, ok)
		require.NotEmpty(t, token)

		assert.NotEqual(t, subject, token)

		rwi, ri := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCIntrospectionEndpoint, url.Values{
			testOIDCFormParameterToken:        []string{token},
			oidc.FormParameterClientID:        []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
		})

		OAuth2IntrospectionPOST(mock.Ctx, rwi, ri)

		require.Equal(t, http.StatusOK, rwi.Code)

		introspection := getTestOAuth2ErrorResponse(t, rwi)

		assert.Equal(t, true, introspection["active"], introspection)
	})

	t.Run("ShouldCarrySubjectUsernameOntoExchangedAccessToken", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator)

		subject := mustGetTestOIDCSubjectAccessToken(t, mock)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{subject},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		response := getTestOAuth2ErrorResponse(t, rw)

		require.Equal(t, http.StatusOK, rw.Code, response)

		token, ok := response["access_token"].(string)

		require.True(t, ok)

		rwi, ri := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCIntrospectionEndpoint, url.Values{
			testOIDCFormParameterToken:        []string{token},
			oidc.FormParameterClientID:        []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
		})

		OAuth2IntrospectionPOST(mock.Ctx, rwi, ri)

		require.Equal(t, http.StatusOK, rwi.Code)

		introspection := getTestOAuth2ErrorResponse(t, rwi)

		assert.Equal(t, true, introspection["active"], introspection)
		assert.Equal(t, "john", introspection["username"], introspection)
	})

	t.Run("ShouldDenyExchangeWhenSubjectClientDoesNotPermitTheRequestingClient", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			subject.SubjectTokenClientsSupported = nil
		})

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{token},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		assert.NotEqual(t, http.StatusOK, rw.Code)

		response := getTestOAuth2ErrorResponse(t, rw)

		assert.Equal(t, "invalid_request", response["error"])
		assert.Contains(t, response["error_description"], "The OAuth 2.0 client is not permitted to exchange a subject token issued to client")
	})

	t.Run("ShouldRejectCrossClientSubjectTokenWithoutRequestingClientAudience", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			subject.Audience = nil
		})

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{token},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		assert.Equal(t, http.StatusBadRequest, rw.Code)

		response := getTestOAuth2ErrorResponse(t, rw)

		assert.Equal(t, "invalid_request", response["error"])
		assert.Contains(t, response["error_description"], "The audience of a subject token does not include the OAuth 2.0 client.")
	})

	t.Run("ShouldDenyDelegationWhenSubjectTokenLacksMayAct", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		// The 'actor_token' options aren't supported, so an 'actor_token' is only accepted from the client performing
		// the exchange itself, and delegation is still refused as no token carries a 'may_act' claim.
		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.GrantTypes = append(exchange.GrantTypes, oidc.GrantTypeAuthorizationCode)
			exchange.ResponseTypes = []string{oidc.ResponseTypeAuthorizationCodeFlow}
			exchange.RedirectURIs = []string{testOIDCRedirectURI}
		})

		subject := mustGetTestOIDCSubjectAccessToken(t, mock)
		actor := mustGetTestOIDCClientAccessToken(t, mock, testOIDCTokenExchangeID)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{subject},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterActorToken:         []string{actor},
			testOIDCFormParameterActorTokenType:     []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		assert.NotEqual(t, http.StatusOK, rw.Code)

		response := getTestOAuth2ErrorResponse(t, rw)

		assert.Equal(t, "invalid_request", response["error"], response)
		assert.Contains(t, response["error_description"], "may_act", response)
	})

	t.Run("ShouldRejectActorTokenWhenOwnerOnlyPermitsSubjectUse", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock)

		subject := mustGetTestOIDCSubjectAccessToken(t, mock)
		actor := mustGetTestOIDCClientAccessToken(t, mock, testOIDCActorID)

		rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
			testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
			oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
			testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
			testOIDCFormParameterSubjectToken:       []string{subject},
			testOIDCFormParameterSubjectTokenType:   []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterActorToken:         []string{actor},
			testOIDCFormParameterActorTokenType:     []string{oidc.TokenTypeAccessToken},
			testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
		})

		OAuth2TokenPOST(mock.Ctx, rw, r)

		assert.NotEqual(t, http.StatusOK, rw.Code)

		response := getTestOAuth2ErrorResponse(t, rw)

		assert.Equal(t, "invalid_request", response["error"], response)
		assert.Contains(t, response["error_description"], "not permitted to exchange an actor token issued to client actor", response)
	})

	ownMutator := func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
		exchange.GrantTypes = append(exchange.GrantTypes, oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken)
		exchange.ResponseTypes = []string{oidc.ResponseTypeAuthorizationCodeFlow}
		exchange.RedirectURIs = []string{testOIDCRedirectURI}
		exchange.Scopes = append(exchange.Scopes, oidc.ScopeOfflineAccess)
		exchange.SubjectTokenTypesSupported = []string{oidc.TokenTypeAccessToken}
	}

	preConfiguredMutator := func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
		duration := time.Hour

		exchange.ConsentMode = "pre-configured"
		exchange.ConsentPreConfiguredDuration = &duration
		exchange.ImpersonationAllowed = true
	}

	t.Run("ShouldRejectCrossClientImpersonationByDefault", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock)

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_request", response["error"], response)
		assert.Contains(t, response["error_description"], "The client is not permitted to perform impersonation; an 'actor_token' is required.", response)
	})

	t.Run("ShouldPermitCrossClientImpersonationWhenAllowed", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator)

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusOK, code, response)
	})

	t.Run("ShouldRejectCrossClientClientCredentialsSubject", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			subject.GrantTypes = append(subject.GrantTypes, oidc.GrantTypeClientCredentials)
			subject.Scopes = append(subject.Scopes, testOIDCScopeBearerAuthz)
		})

		token := mustGetTestOIDCClientCredentialsTokenForClient(t, mock, testOIDCAuthorizationCodeID, testOIDCTokenExchangeID)

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_grant", response["error"], response)
		assert.Contains(t, response["error_description"], "A token issued via the client credentials grant may only be exchanged by the client it was issued to.", response)
	})

	t.Run("ShouldRejectWhenPolicyDenied", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			config.AuthorizationPolicies = map[string]schema.IdentityProvidersOpenIDConnectPolicy{
				"deny-john": {
					DefaultPolicy: "one_factor",
					Rules: []schema.IdentityProvidersOpenIDConnectPolicyRule{
						{Policy: "deny", Subjects: schema.AccessControlRuleSubjects{{"user:" + testUsername}}},
					},
				},
			}

			exchange.AuthorizationPolicy = "deny-john"
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_grant", response["error"], response)
		assert.Contains(t, response["error_description"], "The client's authorization policy does not permit this user.", response)
	})

	t.Run("ShouldRejectWhenPolicyLevelInsufficient", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.AuthorizationPolicy = "two_factor"
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_grant", response["error"], response)
		assert.Contains(t, response["error_description"], "The authentication level of the 'subject_token' is insufficient for the client's authorization policy.", response)
	})

	t.Run("ShouldPermitWhenPolicyLevelSufficient", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(2))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.AuthorizationPolicy = "two_factor"
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusOK, code, response)
	})

	t.Run("ShouldRejectWhenSubjectUserNoLongerExists", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		remove := setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator)

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		remove()

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_grant", response["error"], response)
		// handleOAuth2TokenUserPermitted refuses the removed user before the token exchange policy resolves the subject.
		assert.Contains(t, response["error_description"], "The user the grant was issued to is no longer permitted to log in.", response)
	})

	t.Run("ShouldRejectCrossClientExplicitConsent", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.ConsentMode = "explicit"
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_grant", response["error"], response)
		assert.Contains(t, response["error_description"], "The client requires explicit user consent which cannot be obtained during a token exchange.", response)
	})

	t.Run("ShouldPermitCrossClientImplicitConsent", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.ConsentMode = "implicit"
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusOK, code, response)
	})

	preConfiguredCases := []struct {
		name     string
		config   model.OAuth2ConsentPreConfig
		sector   bool
		expected int
	}{
		{
			"ShouldPermitCrossClientPreConfiguredConsentCovering",
			model.OAuth2ConsentPreConfig{ID: 1, Scopes: model.StringSlicePipeDelimited{oidc.ScopeOpenID, oidc.ScopeProfile}, Audience: model.StringSlicePipeDelimited{testOIDCTokenExchangeID}},
			false,
			http.StatusOK,
		},
		{
			"ShouldPermitCrossClientPreConfiguredConsentCoveringWithDifferentSector",
			model.OAuth2ConsentPreConfig{ID: 1, Scopes: model.StringSlicePipeDelimited{oidc.ScopeOpenID, oidc.ScopeProfile}},
			true,
			http.StatusOK,
		},
		{
			"ShouldRejectCrossClientPreConfiguredConsentPartialScopes",
			model.OAuth2ConsentPreConfig{ID: 1, Scopes: model.StringSlicePipeDelimited{oidc.ScopeOpenID}, Audience: model.StringSlicePipeDelimited{testOIDCTokenExchangeID}},
			false,
			http.StatusBadRequest,
		},
		{
			"ShouldRejectCrossClientPreConfiguredConsentRevoked",
			model.OAuth2ConsentPreConfig{ID: 1, Revoked: true, Scopes: model.StringSlicePipeDelimited{oidc.ScopeOpenID, oidc.ScopeProfile}, Audience: model.StringSlicePipeDelimited{testOIDCTokenExchangeID}},
			false,
			http.StatusBadRequest,
		},
	}

	for _, tc := range preConfiguredCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
			defer mock.Close()

			setupTestOIDCTokenExchangeFlow(t, mock, preConfiguredMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
				if tc.sector {
					exchange.SectorIdentifierURI = &url.URL{Scheme: "https", Host: "sector.example.com"}
				}
			})

			token, ok := mustGetTestOIDCClientTokenResponseWithScope(t, mock, testOIDCAuthorizationCodeID, "openid profile")["access_token"].(string)

			require.True(t, ok)

			subject := mustGetTestOIDCSubject(t, mock, testOIDCTokenExchangeID)

			if tc.sector {
				require.NotEqual(t, mustGetTestOIDCSubject(t, mock, testOIDCAuthorizationCodeID), subject)
			}

			config := tc.config
			config.ClientID = testOIDCTokenExchangeID
			config.Subject = subject
			config.CreatedAt = mock.Ctx.GetClock().Now()

			rows, closer := mocks.NewConsentPreConfigRows(t, config)
			defer closer()

			mock.StorageMock.EXPECT().
				LoadOAuth2ConsentPreConfigurations(gomock.Any(), gomock.Eq(testOIDCTokenExchangeID), gomock.Eq(subject), gomock.Any()).
				Return(rows, nil)

			values := newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken)
			values.Set(oidc.FormParameterScope, "openid profile")

			code, response := doTestOIDCTokenExchange(t, mock, values)

			require.Equal(t, tc.expected, code, response)

			if tc.expected != http.StatusOK {
				assert.Equal(t, "invalid_grant", response["error"], response)
				assert.Contains(t, response["error_description"], "The user has not consented to this client for the requested scopes.", response)
			}
		})
	}

	jwtMutator := func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
		config.Discovery.JWTResponseAccessTokens = true

		exchange.AccessTokenSignedResponseAlg = oidc.SigningAlgRSAUsingSHA256
		exchange.AccessTokenSignedResponseKeyID = testOIDCKeyID
	}

	subjectCases := []struct {
		name   string
		sector bool
	}{
		{"ShouldDeriveExchangedSubjectForRequestingClientSector", true},
		{"ShouldRetainExchangedSubjectForSameSector", false},
	}

	for _, tc := range subjectCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
			defer mock.Close()

			setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, jwtMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
				if tc.sector {
					exchange.SectorIdentifierURI = &url.URL{Scheme: "https", Host: "sector.example.com"}
				}
			})

			original := mustGetTestOIDCSubject(t, mock, testOIDCAuthorizationCodeID).String()
			expected := mustGetTestOIDCSubject(t, mock, testOIDCTokenExchangeID).String()

			if tc.sector {
				require.NotEqual(t, original, expected)
			} else {
				require.Equal(t, original, expected)
			}

			code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

			require.Equal(t, http.StatusOK, code, response)

			exchanged, ok := response["access_token"].(string)

			require.True(t, ok)

			assert.Equal(t, expected, mustDecodeTestJWTClaims(t, exchanged)[oidc.ClaimSubject])

			introspection := mustGetTestOIDCIntrospection(t, mock, exchanged)

			assert.Equal(t, true, introspection["active"], introspection)
			assert.Equal(t, expected, introspection[oidc.ClaimSubject], introspection)
		})
	}

	t.Run("ShouldFailWhenRequestingClientSubjectCannotBeResolved", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		mock.StorageMock.EXPECT().
			LoadUserOpaqueIdentifierBySignature(gomock.Any(), gomock.Any(), gomock.Eq("https://sector.example.com"), gomock.Any()).
			AnyTimes().
			Return(nil, errors.New("bad connection"))

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.SectorIdentifierURI = &url.URL{Scheme: "https", Host: "sector.example.com"}
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusInternalServerError, code, response)
		assert.Equal(t, "server_error", response["error"], response)
	})

	t.Run("ShouldRejectOwnAccessTokenExchangeByDefault", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, ownMutator)

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCClientAccessToken(t, mock, testOIDCTokenExchangeID), oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusBadRequest, code, response)
		assert.Equal(t, "invalid_request", response["error"], response)
		assert.Contains(t, response["error_description"], "Clients are not allowed to perform a token exchange on their own access tokens.", response)
	})

	t.Run("ShouldApplyCustomTokenExchangeGrantLifespan", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			config.Lifespans.Custom = map[string]schema.IdentityProvidersOpenIDConnectLifespan{
				"exchange": {
					Grants: schema.IdentityProvidersOpenIDConnectLifespanGrants{
						TokenExchange: schema.IdentityProvidersOpenIDConnectLifespanToken{AccessToken: 10 * time.Minute},
					},
				},
			}

			exchange.Lifespan = "exchange"
		})

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(mustGetTestOIDCSubjectAccessToken(t, mock), oidc.TokenTypeAccessToken))

		require.Equal(t, http.StatusOK, code, response)

		expiresIn, ok := response["expires_in"].(float64)

		require.True(t, ok, response)
		assert.LessOrEqual(t, expiresIn, float64(600), response)
		assert.Greater(t, expiresIn, float64(590), response)
	})
}

// setupTestOIDCTokenExchangeFlow registers the Authorization Code Flow client whose tokens are exchanged and the
// confidential client which performs the exchange, then wires up the storage mocks. Each mutator is applied to the
// provider and client configurations before the provider is created.
func setupTestOIDCTokenExchangeFlow(t *testing.T, mock *mocks.MockAutheliaCtx, mutators ...testOIDCTokenExchangeMutator) (remove func()) {
	t.Helper()

	subject := newTestOIDCAuthorizationCodeClient(t)
	subject.ConsentMode = "implicit"
	subject.Audience = []string{testOIDCTokenExchangeID}
	subject.RequestedAudienceMode = "implicit"
	subject.SubjectTokenClientsSupported = []schema.IdentityProvidersOpenIDConnectClientTokenExchangePolicy{
		{ClientID: testOIDCTokenExchangeID},
	}

	exchange := newTestOIDCTokenExchangeClient(t)
	exchange.ConsentMode = "implicit"

	config := newTestOIDCConfig(t)

	// The validator applies these defaults to every deployment, so apply them here too; the RFC 8693 token type
	// handlers take their lifespans from these values directly.
	config.Lifespans = schema.DefaultOpenIDConnectConfiguration.Lifespans

	for _, mutator := range mutators {
		mutator(config, &subject, &exchange)
	}

	// The actor client mirrors the subject client under a distinct identity so delegation tests can tell the actor
	// token apart from the subject token.
	actor := subject
	actor.ID = testOIDCActorID

	config.Clients = append([]schema.IdentityProvidersOpenIDConnectClient{subject, actor, exchange}, config.Clients...)

	setupTestOIDCProvider(t, mock, config)
	setupTestOIDCSessionStore(t, mock)
	setupTestOIDCConsentStore(t, mock)
	setupTestOIDCSubjectStore(t, mock)

	return setupTestOIDCRemovableUserDetails(t, mock)
}

func setupTestOIDCRemovableUserDetails(t *testing.T, mock *mocks.MockAutheliaCtx) (remove func()) {
	t.Helper()

	details := newTestOIDCUserDetails()

	removed := false

	mock.UserProviderMock.EXPECT().
		GetDetails(testUsername).
		AnyTimes().
		DoAndReturn(func(_ string) (*authentication.UserDetails, error) {
			if removed {
				return nil, authentication.ErrUserNotFound
			}

			return details, nil
		})

	mock.UserProviderMock.EXPECT().
		GetDetailsExtended(testUsername).
		AnyTimes().
		DoAndReturn(func(_ string) (*authentication.UserDetailsExtended, error) {
			if removed {
				return nil, authentication.ErrUserNotFound
			}

			return &authentication.UserDetailsExtended{UserDetails: details}, nil
		})

	return func() {
		removed = true
	}
}

//nolint:unparam // Upstream also exchanges the refresh token and ID Token types, which aren't supported here.
func newTestOIDCTokenExchangeValues(subject, subjectType string) url.Values {
	return url.Values{
		testOIDCFormParameterGrantType:          []string{oidc.GrantTypeTokenExchange},
		oidc.FormParameterClientID:              []string{testOIDCTokenExchangeID},
		testOIDCFormParameterClientSecret:       []string{testOIDCClientSecretValue},
		testOIDCFormParameterSubjectToken:       []string{subject},
		testOIDCFormParameterSubjectTokenType:   []string{subjectType},
		testOIDCFormParameterRequestedTokenType: []string{oidc.TokenTypeAccessToken},
	}
}

func doTestOIDCTokenExchange(t *testing.T, mock *mocks.MockAutheliaCtx, values url.Values) (code int, response map[string]any) {
	t.Helper()

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, values)

	OAuth2TokenPOST(mock.Ctx, rw, r)

	return rw.Code, getTestOAuth2ErrorResponse(t, rw)
}

func mustGetTestOIDCIntrospection(t *testing.T, mock *mocks.MockAutheliaCtx, token string) (introspection map[string]any) {
	t.Helper()

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCIntrospectionEndpoint, url.Values{
		testOIDCFormParameterToken:        []string{token},
		oidc.FormParameterClientID:        []string{testOIDCTokenExchangeID},
		testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
	})

	OAuth2IntrospectionPOST(mock.Ctx, rw, r)

	require.Equal(t, http.StatusOK, rw.Code)

	return getTestOAuth2ErrorResponse(t, rw)
}

func mustGetTestOIDCClientCredentialsTokenForClient(t *testing.T, mock *mocks.MockAutheliaCtx, clientID, audience string) (token string) {
	t.Helper()

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
		testOIDCFormParameterGrantType:    []string{oidc.GrantTypeClientCredentials},
		oidc.FormParameterClientID:        []string{clientID},
		testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
		oidc.FormParameterScope:           []string{testOIDCScopeBearerAuthz},
		testOIDCFormParameterAudience:     []string{audience},
	})

	OAuth2TokenPOST(mock.Ctx, rw, r)

	response := getTestOAuth2ErrorResponse(t, rw)

	require.Equal(t, http.StatusOK, rw.Code, response)

	token, ok := response["access_token"].(string)

	require.True(t, ok)
	require.NotEmpty(t, token)

	return token
}

func newTestOIDCTokenExchangeClient(t *testing.T) schema.IdentityProvidersOpenIDConnectClient {
	t.Helper()

	// A Token Exchange client is confidential and authenticates at the token endpoint just as a Client Credentials
	// Flow client does, so the base configuration is shared.
	client := newTestOIDCClientCredentialsClient(t)

	client.ID = testOIDCTokenExchangeID
	client.GrantTypes = []string{oidc.GrantTypeTokenExchange}
	client.Scopes = []string{oidc.ScopeOpenID, oidc.ScopeProfile}
	client.Audience = nil

	return client
}

// mustGetTestOIDCSubjectAccessToken performs the Authorization Code Flow as the subject client and returns the issued
// access token, which is the 'subject_token' of the exchange.
func mustGetTestOIDCSubjectAccessToken(t *testing.T, mock *mocks.MockAutheliaCtx) (token string) {
	t.Helper()

	return mustGetTestOIDCClientAccessToken(t, mock, testOIDCAuthorizationCodeID)
}

// mustGetTestOIDCClientAccessToken performs the Authorization Code Flow as the given client and returns the issued
// access token.
func mustGetTestOIDCClientAccessToken(t *testing.T, mock *mocks.MockAutheliaCtx, clientID string) (token string) {
	t.Helper()

	token, ok := mustGetTestOIDCClientTokenResponse(t, mock, clientID)["access_token"].(string)

	require.True(t, ok)
	require.NotEmpty(t, token)

	return token
}

func mustGetTestOIDCClientTokenResponse(t *testing.T, mock *mocks.MockAutheliaCtx, clientID string) (response map[string]any) {
	t.Helper()

	return mustGetTestOIDCClientTokenResponseWithScope(t, mock, clientID, oidc.ScopeOpenID)
}

func mustGetTestOIDCClientTokenResponseWithScope(t *testing.T, mock *mocks.MockAutheliaCtx, clientID, scope string) (response map[string]any) {
	t.Helper()

	values := newTestOIDCAuthorizationValues()
	values.Set(oidc.FormParameterClientID, clientID)
	values.Set(oidc.FormParameterScope, scope)

	code := mustGetTestOIDCAuthorizationCode(t, mock, values)

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
		testOIDCFormParameterGrantType:    []string{oidc.GrantTypeAuthorizationCode},
		oidc.FormParameterClientID:        []string{clientID},
		testOIDCFormParameterClientSecret: []string{testOIDCClientSecretValue},
		testOIDCFormParameterCode:         []string{code},
		oidc.FormParameterRedirectURI:     []string{testOIDCRedirectURI},
	})

	OAuth2TokenPOST(mock.Ctx, rw, r)

	response = getTestOAuth2ErrorResponse(t, rw)

	require.Equal(t, http.StatusOK, rw.Code, response)

	return response
}

func mustDecodeTestJWTClaims(t *testing.T, token string) (claims map[string]any) {
	t.Helper()

	parts := strings.Split(token, ".")

	require.Len(t, parts, 3, "the token should be a JWT")

	data, err := base64.RawURLEncoding.DecodeString(parts[1])

	require.NoError(t, err)

	claims = map[string]any{}

	require.NoError(t, json.Unmarshal(data, &claims))

	return claims
}

func mustGetTestJWTAudience(t *testing.T, claims map[string]any) (audience []string) {
	t.Helper()

	switch value := claims[oidc.ClaimAudience].(type) {
	case string:
		return []string{value}
	case []any:
		for _, item := range value {
			str, ok := item.(string)

			require.True(t, ok)

			audience = append(audience, str)
		}

		return audience
	case nil:
		return nil
	default:
		t.Fatalf("unexpected 'aud' claim type %T", value)

		return nil
	}
}

func TestIsOAuth2TokenExchangeOwnToken(t *testing.T) {
	testCases := []struct {
		name        string
		owner       oauthelia2.Client
		stored      bool
		subjectType string
		expected    bool
	}{
		{"ShouldBeOwnForStoredSubjectOfRequestingClient", &oidc.RegisteredClient{ID: testOIDCTokenExchangeID}, true, oidc.TokenTypeAccessToken, true},
		{"ShouldBeCrossClientForStoredSubjectOfAnotherClient", &oidc.RegisteredClient{ID: testOIDCAuthorizationCodeID}, true, oidc.TokenTypeAccessToken, false},
		{"ShouldBeCrossClientForStoredSubjectOfAnotherClientClaimingIDToken", &oidc.RegisteredClient{ID: testOIDCAuthorizationCodeID}, true, oidc.TokenTypeIDToken, false},
		// The fork never takes an ID Token for the client's own token, which would skip the consent and impersonation checks.
		{"ShouldNotBeOwnForNonStoredIDTokenSubject", nil, false, oidc.TokenTypeIDToken, false},
		{"ShouldBeCrossClientForNonStoredJWTSubject", nil, false, "urn:ietf:params:oauth:token-type:jwt", false},
		{"ShouldBeCrossClientForNonStoredAccessTokenSubject", nil, false, oidc.TokenTypeAccessToken, false},
		{"ShouldBeCrossClientForNonStoredSubjectWithoutType", nil, false, "", false},
		{"ShouldBeCrossClientForStoredSubjectWithoutClient", nil, true, oidc.TokenTypeAccessToken, false},
		{"ShouldBeCrossClientForStoredSubjectWithoutClientClaimingIDToken", nil, true, oidc.TokenTypeIDToken, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session := oidc.NewSession()

			if tc.stored {
				session.SetSubjectRequester(&oauthelia2.Request{Client: tc.owner, Session: oidc.NewSession()})
			}

			requester := &oauthelia2.AccessRequest{
				Request: oauthelia2.Request{
					Form:    url.Values{testOIDCFormParameterSubjectTokenType: []string{tc.subjectType}},
					Session: session,
				},
			}

			assert.Equal(t, tc.expected, isOAuth2TokenExchangeOwnToken(requester, &oidc.RegisteredClient{ID: testOIDCTokenExchangeID}, session))
		})
	}
}

func getTestOIDCTokenExchangeAuditEntries(mock *mocks.MockAutheliaCtx) (entries []*logrus.Entry) {
	for _, entry := range mock.Hook.AllEntries() {
		if strings.HasPrefix(entry.Message, "Token Exchange ") {
			entries = append(entries, entry)
		}
	}

	return entries
}

func TestOAuth2TokenPOSTTokenExchangeAudit(t *testing.T) {
	t.Run("ShouldLogCompletedExchange", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			exchange.ImpersonationAllowed = true
		})

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		mock.Hook.Reset()

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		require.Equal(t, http.StatusOK, code, response)

		entries := getTestOIDCTokenExchangeAuditEntries(mock)

		require.Len(t, entries, 1)

		entry := entries[0]

		assert.Equal(t, logrus.InfoLevel, entry.Level)
		assert.Equal(t, "Token Exchange completed", entry.Message)
		assert.Equal(t, testOIDCTokenExchangeID, entry.Data["client_id"])
		assert.Equal(t, testUsername, entry.Data["username"])
		assert.NotEmpty(t, entry.Data["subject"])
		assert.NotEmpty(t, entry.Data["oauth2_access_request_id"])
		assert.Equal(t, oidc.TokenTypeAccessToken, entry.Data["subject_token_type"])
		assert.Equal(t, oidc.TokenTypeAccessToken, entry.Data["requested_token_type"])
		assert.Equal(t, oidc.TokenTypeAccessToken, entry.Data["issued_token_type"])
		assert.Equal(t, testOIDCAuthorizationCodeID, entry.Data["subject_token_client_id"])
		assert.Equal(t, true, entry.Data["impersonation"])

		for _, e := range mock.Hook.AllEntries() {
			assert.NotContains(t, e.Message, token)

			for _, v := range e.Data {
				assert.NotContains(t, fmt.Sprint(v), token)
			}
		}
	})

	t.Run("ShouldLogImpersonationDenial", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock)

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		mock.Hook.Reset()

		code, _ := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		require.Equal(t, http.StatusBadRequest, code)

		entries := getTestOIDCTokenExchangeAuditEntries(mock)

		require.Len(t, entries, 1)

		assert.Equal(t, logrus.WarnLevel, entries[0].Level)
		assert.Equal(t, "Token Exchange denied", entries[0].Message)
		assert.Equal(t, testOIDCTokenExchangeID, entries[0].Data["client_id"])
		assert.Contains(t, fmt.Sprint(entries[0].Data["error"]), "The client is not permitted to perform impersonation")

		for _, e := range mock.Hook.AllEntries() {
			if e.Level <= logrus.ErrorLevel {
				assert.NotContains(t, e.Message, "Token Exchange policy")
			}
		}

		for _, e := range mock.Hook.AllEntries() {
			assert.NotContains(t, e.Message, token)

			for _, v := range e.Data {
				assert.NotContains(t, fmt.Sprint(v), token)
			}
		}
	})

	t.Run("ShouldLogLibraryDenial", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			subject.SubjectTokenClientsSupported = nil
		})

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		mock.Hook.Reset()

		code, _ := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		require.NotEqual(t, http.StatusOK, code)

		entries := getTestOIDCTokenExchangeAuditEntries(mock)

		require.Len(t, entries, 1)

		assert.Equal(t, logrus.WarnLevel, entries[0].Level)
		assert.Equal(t, "Token Exchange denied", entries[0].Message)
		assert.Equal(t, testOIDCTokenExchangeID, entries[0].Data["client_id"])
		assert.Equal(t, oidc.TokenTypeAccessToken, entries[0].Data["subject_token_type"])
		assert.NotEmpty(t, entries[0].Data["error"])

		for _, e := range mock.Hook.AllEntries() {
			assert.NotContains(t, fmt.Sprint(e.Data), token)
		}
	})

	t.Run("ShouldLogJWTProfileHydrationFailure", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		var (
			armed bool
			calls int
		)

		mock.UserProviderMock.EXPECT().
			GetDetailsExtended(testUsername).
			AnyTimes().
			DoAndReturn(func(_ string) (*authentication.UserDetailsExtended, error) {
				if armed {
					calls++

					if calls > 1 {
						return nil, errors.New("backend unavailable")
					}
				}

				return &authentication.UserDetailsExtended{UserDetails: newTestOIDCUserDetails()}, nil
			})

		setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
			config.Discovery.JWTResponseAccessTokens = true

			exchange.AccessTokenSignedResponseAlg = oidc.SigningAlgRSAUsingSHA256
			exchange.AccessTokenSignedResponseKeyID = testOIDCKeyID
			exchange.ImpersonationAllowed = true
		})

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		mock.Hook.Reset()

		armed = true

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		require.NotEqual(t, http.StatusOK, code, response)
		require.Equal(t, 2, calls)

		entries := getTestOIDCTokenExchangeAuditEntries(mock)

		require.Len(t, entries, 1)

		assert.Equal(t, logrus.WarnLevel, entries[0].Level)
		assert.Equal(t, "Token Exchange denied", entries[0].Message)
		assert.Equal(t, testOIDCTokenExchangeID, entries[0].Data["client_id"])
		assert.NotEmpty(t, entries[0].Data["error"])
	})

	t.Run("ShouldNotLogWhenClientAuthenticationFails", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock)

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		mock.Hook.Reset()

		values := newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken)
		values.Set(testOIDCFormParameterClientSecret, "not-the-secret")

		code, _ := doTestOIDCTokenExchange(t, mock, values)

		require.Equal(t, http.StatusUnauthorized, code)
		assert.Empty(t, getTestOIDCTokenExchangeAuditEntries(mock))
	})
}

// TestHandleOAuth2TokenExchangePolicyRefusesActorTokens checks the fork's up-front refusal of delegation directly: the
// library refuses an actor token without a 'may_act' claim first in a full request, which would hide a regression here.
func TestHandleOAuth2TokenExchangePolicyRefusesActorTokens(t *testing.T) {
	for _, form := range []url.Values{
		{oidc.FormParameterActorToken: []string{"a-token"}},
		{oidc.FormParameterActorTokenType: []string{oidc.TokenTypeAccessToken}},
	} {
		mock := mocks.NewMockAutheliaCtx(t)

		requester := &oauthelia2.AccessRequest{Request: oauthelia2.Request{Form: form, Session: oidc.NewSession()}}

		details, err := handleOAuth2TokenExchangePolicy(mock.Ctx, requester, &oidc.RegisteredClient{ID: testOIDCTokenExchangeID, ImpersonationAllowed: true}, oidc.NewSession())

		assert.Nil(t, details)
		require.Error(t, err)
		assert.Contains(t, oauthelia2.ErrorToDebugRFC6749Error(err).Error(), "The 'actor_token' is not supported.")

		mock.Close()
	}
}
