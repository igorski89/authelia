// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestValidateOIDCClientConsentImplicitOfflineAccess(t *testing.T) {
	testCases := []struct {
		name     string
		client   schema.IdentityProvidersOpenIDConnectClient
		expected string
	}{
		{"ShouldAllowImplicitConfidential", schema.IdentityProvidersOpenIDConnectClient{ID: "a", ConsentMode: "implicit", ConsentImplicitOfflineAccess: true}, ""},
		{"ShouldIgnoreUnset", schema.IdentityProvidersOpenIDConnectClient{ID: "a", ConsentMode: "explicit", Public: true}, ""},
		{"ShouldRefuseOtherModes", schema.IdentityProvidersOpenIDConnectClient{ID: "a", ConsentMode: "pre-configured", ConsentImplicitOfflineAccess: true}, "identity_providers: oidc: clients: client 'a': option 'consent_implicit_offline_access' requires the 'consent_mode' to be 'implicit' but it's configured as 'pre-configured'"},
		{"ShouldRefusePublicClients", schema.IdentityProvidersOpenIDConnectClient{ID: "a", ConsentMode: "implicit", Public: true, ConsentImplicitOfflineAccess: true}, "identity_providers: oidc: clients: client 'a': option 'consent_implicit_offline_access' can't be used with a public client"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &schema.IdentityProvidersOpenIDConnect{Clients: []schema.IdentityProvidersOpenIDConnectClient{tc.client}}
			validator := schema.NewStructValidator()

			validateOIDCClientConsentImplicitOfflineAccess(0, config, validator)

			if tc.expected == "" {
				assert.Empty(t, validator.Errors())

				return
			}

			require.Len(t, validator.Errors(), 1)
			assert.EqualError(t, validator.Errors()[0], tc.expected)
		})
	}
}
