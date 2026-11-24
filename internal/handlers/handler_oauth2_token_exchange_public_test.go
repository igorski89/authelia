// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/valyala/fasthttp"
	"go.uber.org/mock/gomock"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/storage"
)

// TestOAuth2TokenPOSTTokenExchangePublicSubjectClient exchanges a JWT access token issued to a public client via the
// Authorization Code Flow with PKCE, whose audience is the confidential client performing the exchange, for an access
// token of that confidential client without an 'actor_token' (impersonation).
func TestOAuth2TokenPOSTTokenExchangePublicSubjectClient(t *testing.T) {
	const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXkdBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

	mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
	defer mock.Close()

	setupTestOIDCTokenExchangeFlow(t, mock, func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
		config.Discovery.JWTResponseAccessTokens = true

		subject.Public = true
		subject.Secret = nil
		subject.TokenEndpointAuthMethod = oidc.ClientAuthMethodNone
		subject.AccessTokenSignedResponseAlg = oidc.SigningAlgRSAUsingSHA256
		subject.AccessTokenSignedResponseKeyID = testOIDCKeyID

		exchange.ImpersonationAllowed = true
		exchange.AccessTokenSignedResponseAlg = oidc.SigningAlgRSAUsingSHA256
		exchange.AccessTokenSignedResponseKeyID = testOIDCKeyID
		exchange.SectorIdentifierURI = &url.URL{Scheme: "https", Host: "sector.example.com"}
	})

	mock.StorageMock.EXPECT().
		SaveOAuth2RequestReplay(gomock.Any(), gomock.Any()).
		AnyTimes().
		Return(nil)

	challenge := sha256.Sum256([]byte(verifier))

	values := newTestOIDCAuthorizationValues()
	values.Set("code_challenge", base64.RawURLEncoding.EncodeToString(challenge[:]))
	values.Set("code_challenge_method", oidc.PKCEChallengeMethodSHA256)

	code := mustGetTestOIDCAuthorizationCode(t, mock, values)

	rw, r := newTestOAuth2Request(t, fasthttp.MethodPost, testOIDCTokenEndpoint, url.Values{
		testOIDCFormParameterGrantType: []string{oidc.GrantTypeAuthorizationCode},
		oidc.FormParameterClientID:     []string{testOIDCAuthorizationCodeID},
		testOIDCFormParameterCode:      []string{code},
		oidc.FormParameterRedirectURI:  []string{testOIDCRedirectURI},
		"code_verifier":                []string{verifier},
	})

	OAuth2TokenPOST(mock.Ctx, rw, r)

	response := getTestOAuth2ErrorResponse(t, rw)

	require.Equal(t, http.StatusOK, rw.Code, response)

	token, ok := response["access_token"].(string)

	require.True(t, ok)

	original := mustDecodeTestJWTClaims(t, token)

	assert.Equal(t, []string{testOIDCTokenExchangeID}, mustGetTestJWTAudience(t, original))
	assert.Equal(t, testOIDCAuthorizationCodeID, original[oidc.ClaimClientIdentifier])

	code2, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

	require.Equal(t, http.StatusOK, code2, response)

	exchanged, ok := response["access_token"].(string)

	require.True(t, ok)

	claims := mustDecodeTestJWTClaims(t, exchanged)

	expected := mustGetTestOIDCSubject(t, mock, testOIDCTokenExchangeID).String()

	require.NotEqual(t, original[oidc.ClaimSubject], expected, "the clients have different sectors")

	assert.Equal(t, expected, claims[oidc.ClaimSubject], "the subject is derived for the sector of the requesting client")
	assert.Equal(t, testOIDCTokenExchangeID, claims[oidc.ClaimClientIdentifier])
	assert.NotContains(t, claims, oidc.ClaimActor)

	row, err := mock.Ctx.Providers.StorageProvider.LoadOAuth2Session(mock.Ctx, storage.OAuth2SessionTypeAccessToken, mock.Ctx.Providers.OpenIDConnect.Strategy.Core.AccessTokenSignature(mock.Ctx, exchanged))

	require.NoError(t, err)

	assert.Equal(t, testOIDCTokenExchangeID, row.ClientID)
	assert.Equal(t, expected, row.Subject.String, "the stored subject is the one of the requesting client's sector")

	stored := oidc.NewSession()

	require.NoError(t, json.Unmarshal(row.Session, stored))

	assert.Equal(t, testUsername, stored.Username)
	assert.Equal(t, testOIDCTokenExchangeID, stored.ClientID)
	assert.False(t, stored.ClientCredentials)
	assert.False(t, stored.ChallengeID.Valid, "the consent of the subject token's client isn't carried")
	assert.Equal(t, expected, stored.Claims.Subject)
	assert.Equal(t, testOIDCTokenExchangeID, stored.Claims.AuthorizedParty)
	assert.Empty(t, stored.Claims.Audience)
	assert.Empty(t, stored.Claims.Nonce)
	assert.NotNil(t, stored.Claims.AuthTime, "the authentication of the subject token is carried")
	assert.NotEmpty(t, stored.Claims.AuthenticationMethodsReferences, "the authentication of the subject token is carried")
	assert.Nil(t, stored.SubjectToken, "the subject token claims aren't persisted")

	introspection := mustGetTestOIDCIntrospection(t, mock, exchanged)

	assert.Equal(t, true, introspection["active"], introspection)
	assert.Equal(t, testUsername, introspection["username"], introspection)
	assert.Equal(t, testOIDCTokenExchangeID, introspection[oidc.ClaimClientIdentifier], introspection)
	assert.Equal(t, expected, introspection[oidc.ClaimSubject], introspection)
}
