// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// testRevokingStorage returns the given revocation marks for every user and defers everything else to the mock.
type testRevokingStorage struct {
	*mocks.MockStorage

	revocations []model.UserRevocation
}

func (s *testRevokingStorage) LoadUserRevocations(_ context.Context, _ string) ([]model.UserRevocation, error) {
	return s.revocations, nil
}

// TestOAuth2TokenPOSTTokenExchangeRevoked checks that an RFC 8693 Token Exchange is refused when the grant the
// 'subject_token' was issued for was revoked by a logout, of the client it was issued to or of the client performing
// the exchange, after it was authorized.
func TestOAuth2TokenPOSTTokenExchangeRevoked(t *testing.T) {
	impersonationMutator := func(config *schema.IdentityProvidersOpenIDConnect, subject, exchange *schema.IdentityProvidersOpenIDConnectClient) {
		exchange.ImpersonationAllowed = true
	}

	testCases := []struct {
		name     string
		clientID string
		expected int
	}{
		{"ShouldRejectWhenSubjectTokenClientRevoked", testOIDCAuthorizationCodeID, http.StatusBadRequest},
		{"ShouldRejectWhenRequestingClientRevoked", testOIDCTokenExchangeID, http.StatusBadRequest},
		{"ShouldRejectWhenAllClientsRevoked", "", http.StatusBadRequest},
		{"ShouldPermitWhenAnotherClientRevoked", "other", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
			defer mock.Close()

			setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator)

			token := mustGetTestOIDCSubjectAccessToken(t, mock)

			mock.Ctx.Providers.StorageProvider = &testRevokingStorage{
				MockStorage: mock.StorageMock,
				revocations: []model.UserRevocation{{Username: testUsername, ClientID: tc.clientID, RevokedAt: mock.Ctx.GetClock().Now().Add(time.Minute)}},
			}

			// The revocation marks of the user are cached on the request by the requests made to obtain the token.
			mock.Ctx.ResetUserValues()

			code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

			assert.Equal(t, tc.expected, code, response)

			if tc.expected != http.StatusOK {
				assert.Equal(t, "invalid_grant", response["error"], response)
				assert.Contains(t, response["error_description"], "The grant was revoked since the user logged in.", response)
			}
		})
	}

	t.Run("ShouldPermitWhenRevokedBeforeSubjectTokenWasAuthorized", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtxWithUserSession(t, newTestOIDCUserSession(1))
		defer mock.Close()

		setupTestOIDCTokenExchangeFlow(t, mock, impersonationMutator)

		token := mustGetTestOIDCSubjectAccessToken(t, mock)

		mock.Ctx.Providers.StorageProvider = &testRevokingStorage{
			MockStorage: mock.StorageMock,
			revocations: []model.UserRevocation{{Username: testUsername, RevokedAt: mock.Ctx.GetClock().Now().Add(-time.Hour)}},
		}

		mock.Ctx.ResetUserValues()

		code, response := doTestOIDCTokenExchange(t, mock, newTestOIDCTokenExchangeValues(token, oidc.TokenTypeAccessToken))

		assert.Equal(t, http.StatusOK, code, response)
	})
}
