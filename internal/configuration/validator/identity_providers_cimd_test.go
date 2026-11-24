// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
)

func newTestCIMDConfig(rules ...schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule) *schema.IdentityProvidersOpenIDConnect {
	return &schema.IdentityProvidersOpenIDConnect{
		Discovery: schema.IdentityProvidersOpenIDConnectDiscovery{AuthorizationPolicies: []string{policyOneFactor, policyTwoFactor}},
		Clients:   []schema.IdentityProvidersOpenIDConnectClient{{ID: "gateway"}},
		ClientIDMetadataDocuments: schema.IdentityProvidersOpenIDConnectClientIDMetadataDocuments{
			Enabled: true,
			Rules:   rules,
		},
	}
}

func cimdErrors(validator *schema.StructValidator) (errs []string) {
	for _, err := range validator.Errors() {
		errs = append(errs, err.Error())
	}

	return errs
}

func TestValidateOIDCClientIDMetadataDocumentsDefaults(t *testing.T) {
	config := newTestCIMDConfig(schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai", Audience: []string{"gateway"}, Scopes: []string{"openid", "offline_access"}})
	validator := schema.NewStructValidator()

	validateOIDCClientIDMetadataDocuments(NewValidateCtx(), config, validator)

	require.Empty(t, cimdErrors(validator))

	cimd := config.ClientIDMetadataDocuments
	assert.Equal(t, 5*time.Second, cimd.FetchTimeout)
	assert.Equal(t, 5120, cimd.MaxDocumentBytes)
	assert.Equal(t, time.Hour, cimd.CacheLifespan)
	assert.Equal(t, 24*time.Hour, cimd.MaxCacheLifespan)
	assert.Equal(t, 20, cimd.MaxDocumentsPerHost)
	assert.Equal(t, 100, cimd.MaxDocumentsPerDomain)
	assert.Empty(t, validator.Warnings())

	rule := cimd.Rules[0]
	assert.Equal(t, oidc.ClientConsentModeExplicit.String(), rule.ConsentMode)

	client := rule.Client
	assert.True(t, client.Public)
	assert.Equal(t, oidc.ClientAuthMethodNone, client.TokenEndpointAuthMethod)
	assert.Equal(t, oidc.PKCEChallengeMethodSHA256, client.PKCEChallengeMethod)
	assert.Equal(t, []string{oidc.GrantTypeAuthorizationCode, oidc.GrantTypeRefreshToken}, client.GrantTypes)
	assert.Equal(t, []string{oidc.ResponseTypeAuthorizationCodeFlow}, client.ResponseTypes)
	assert.Equal(t, policyTwoFactor, client.AuthorizationPolicy)
	assert.Len(t, config.Clients, 1, "the template client must not become a registered client")
}

func TestValidateOIDCClientIDMetadataDocumentsRefusals(t *testing.T) {
	testCases := []struct {
		name     string
		mutate   func(config *schema.IdentityProvidersOpenIDConnect)
		expected string
	}{
		{"ShouldRequireRules", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.Rules = nil }, "option 'rules' must have at least one rule"},
		{"ShouldRefuseDisabledGuard", func(c *schema.IdentityProvidersOpenIDConnect) { c.SpecialUseAddressGuard.Disable = true }, "special_use_address_guard.disable"},
		{"ShouldRefuseEmptyDomain", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.Rules[0].Domain = "." }, "option 'domain' must be a host name"},
		{"ShouldRefuseIPDomain", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Domain = "10.0.0.1"
		}, "option 'domain' must be a host name"},
		{"ShouldRefuseURLDomain", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Domain = "https://claude.ai"
		}, "option 'domain' must be a host name"},
		{"ShouldRefuseUppercaseDomain", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Domain = "Claude.ai"
		}, "option 'domain' must be a host name"},
		{"ShouldRefuseImplicitConsent", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].ConsentMode = "implicit"
		}, "option 'consent_mode' must not be 'implicit'"},
		{"ShouldRefuseAdminScope", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Scopes = []string{"openid", oidc.ScopeAutheliaAdminRead}
		}, "option 'scopes' must not contain 'authelia.admin.read'"},
		{"ShouldRefuseUnregisteredAudience", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Audience = []string{"https://cloud.example.com"}
		}, "option 'audience' must only contain registered client IDs"},
		{"ShouldRefuseUnknownPolicy", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].AuthorizationPolicy = "nope"
		}, "authorization_policy"},
		{"ShouldRefuseOverlappingSubdomains", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules = append(c.ClientIDMetadataDocuments.Rules, schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: ".ai"})
		}, "overlaps the domain"},
		{"ShouldRefuseDuplicateDomain", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules = append(c.ClientIDMetadataDocuments.Rules, schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai"})
		}, "overlaps the domain"},
		{"ShouldRefuseNegativeTimeout", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.FetchTimeout = -time.Second
		}, "option 'fetch_timeout' must be more than 0"},
		{"ShouldRefuseLargeDocuments", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.MaxDocumentBytes = 1 << 20 }, "option 'max_document_bytes' must be at most"},
		{"ShouldRefusePublicSuffix", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Domain = ".github.io"
		}, "must not be a public suffix"},
		{"ShouldRefuseTopLevelDomain", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.Rules[0].Domain = "ai" }, "must not be a public suffix"},
		{"ShouldRefuseICANNSuffix", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.Rules[0].Domain = ".co.uk" }, "must not be a public suffix"},
		{"ShouldRefuseInvalidPort", func(c *schema.IdentityProvidersOpenIDConnect) {
			c.ClientIDMetadataDocuments.Rules[0].Ports = []int{70000}
		}, "option 'ports' must only contain ports"},
		{"ShouldRefuseNegativeDocumentsPerDomain", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.MaxDocumentsPerDomain = -1 }, "option 'max_documents_per_domain' must be more than 0"},
		{"ShouldRefuseNegativeDocumentsPerHost", func(c *schema.IdentityProvidersOpenIDConnect) { c.ClientIDMetadataDocuments.MaxDocumentsPerHost = -1 }, "option 'max_documents_per_host' must be more than 0"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newTestCIMDConfig(schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai"})
			tc.mutate(config)

			validator := schema.NewStructValidator()

			validateOIDCClientIDMetadataDocuments(NewValidateCtx(), config, validator)

			errs := cimdErrors(validator)
			assert.True(t, len(errs) > 0 && strings.Contains(strings.Join(errs, "\n"), tc.expected), "%v", errs)
		})
	}
}

func TestValidateOIDCClientIDMetadataDocumentsExactAndSubdomainRulesDontOverlap(t *testing.T) {
	config := newTestCIMDConfig(
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "claude.ai"},
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: ".claude.ai"},
	)
	validator := schema.NewStructValidator()

	validateOIDCClientIDMetadataDocuments(NewValidateCtx(), config, validator)

	assert.Empty(t, cimdErrors(validator))
}

func TestValidateOIDCClientIDMetadataDocumentsDisabled(t *testing.T) {
	config := newTestCIMDConfig()
	config.ClientIDMetadataDocuments.Enabled = false

	validator := schema.NewStructValidator()

	validateOIDCClientIDMetadataDocuments(NewValidateCtx(), config, validator)

	assert.Empty(t, cimdErrors(validator))
}

func TestValidateOIDCClientIDMetadataDocumentsLocalhostAndSubdomainRule(t *testing.T) {
	config := newTestCIMDConfig(
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: "localhost"},
		schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule{Domain: ".claude.ai", Ports: []int{8443}},
	)
	validator := schema.NewStructValidator()

	validateOIDCClientIDMetadataDocuments(NewValidateCtx(), config, validator)

	assert.Empty(t, cimdErrors(validator))
}
