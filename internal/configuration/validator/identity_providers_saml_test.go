// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func newSAMLTestConfig() *schema.Configuration {
	return &schema.Configuration{
		IdentityProviders: schema.IdentityProviders{
			SAML: &schema.IdentityProvidersSAML{
				Key:              keyRSA2048,
				CertificateChain: certRSA2048,
				ServiceProviders: []schema.IdentityProvidersSAMLServiceProvider{
					{
						EntityID:                     "https://sp.example.com/saml/metadata",
						AssertionConsumerServiceURLs: []url.URL{*MustParseURL("https://sp.example.com/saml/acs")},
					},
				},
			},
		},
	}
}

func TestValidateSAMLDefaults(t *testing.T) {
	config := newSAMLTestConfig()
	validator := schema.NewStructValidator()

	validateSAML(config, validator)

	require.Empty(t, validator.Errors())

	sp := config.IdentityProviders.SAML.ServiceProviders[0]

	assert.Equal(t, 5*time.Minute, config.IdentityProviders.SAML.AssertionLifespan)
	assert.Equal(t, "email", sp.NameIDFormat)
	assert.Equal(t, "two_factor", sp.AuthorizationPolicy)
	assert.Equal(t, "both", sp.Sign)
}

func TestValidateSAMLErrors(t *testing.T) {
	testCases := []struct {
		name     string
		setup    func(config *schema.IdentityProvidersSAML)
		expected string
	}{
		{"ShouldRequireKey", func(c *schema.IdentityProvidersSAML) { c.Key = nil }, "option 'key' is required"},
		{"ShouldRefuseSmallRSAKey", func(c *schema.IdentityProvidersSAML) { c.Key = keyRSA1024 }, "at least 2048 bits"},
		{"ShouldRequireCertificate", func(c *schema.IdentityProvidersSAML) { c.CertificateChain = schema.X509CertificateChain{} }, "option 'certificate_chain' is required"},
		{"ShouldRequireMatchingCertificate", func(c *schema.IdentityProvidersSAML) { c.Key = keyECDSAP256 }, "must be the certificate of option 'key'"},
		{"ShouldRequireServiceProvider", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders = nil }, "at least one service provider"},
		{"ShouldRequireEntityID", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders[0].EntityID = "" }, "option 'entity_id' is required"},
		{"ShouldRequireUniqueEntityID", func(c *schema.IdentityProvidersSAML) {
			c.ServiceProviders = append(c.ServiceProviders, c.ServiceProviders[0])
		}, "must be unique"},
		{"ShouldRequireHTTPS", func(c *schema.IdentityProvidersSAML) {
			c.ServiceProviders[0].AssertionConsumerServiceURLs = []url.URL{*MustParseURL("http://sp.example.com/acs")}
		}, "absolute https URLs"},
		{"ShouldRequireACS", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders[0].AssertionConsumerServiceURLs = nil }, "at least one URL"},
		{"ShouldRefuseNameIDFormat", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders[0].NameIDFormat = "persistent" }, "option 'name_id_format' must be one of"},
		{"ShouldRefusePolicy", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders[0].AuthorizationPolicy = "bypass" }, "option 'authorization_policy' must be one of"},
		{"ShouldRefuseSign", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders[0].Sign = "none" }, "option 'sign' must be one of"},
		{"ShouldRefuseAttribute", func(c *schema.IdentityProvidersSAML) { c.ServiceProviders[0].Attributes = []string{"password"} }, "option 'attributes' must only have"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := newSAMLTestConfig()
			tc.setup(config.IdentityProviders.SAML)

			validator := schema.NewStructValidator()
			validateSAML(config, validator)

			require.NotEmpty(t, validator.Errors())
			assert.Contains(t, validator.Errors()[0].Error(), tc.expected)
		})
	}
}

func TestValidateSAMLRequestSignature(t *testing.T) {
	config := newSAMLTestConfig()
	validator := schema.NewStructValidator()

	validateSAML(config, validator)
	require.Empty(t, validator.Errors())
	assert.Equal(t, "verify", config.IdentityProviders.SAML.ServiceProviders[0].RequestSignature)

	config = newSAMLTestConfig()
	config.IdentityProviders.SAML.ServiceProviders[0].RequestSignature = "skip"
	validator = schema.NewStructValidator()

	validateSAML(config, validator)
	require.NotEmpty(t, validator.Errors())
	assert.Contains(t, validator.Errors()[0].Error(), "option 'request_signature' must be one of")

	config = newSAMLTestConfig()
	config.IdentityProviders.SAML.ServiceProviders[0].RequestSignature = "ignore"
	config.IdentityProviders.SAML.ServiceProviders[0].Certificate = certRSA2048
	validator = schema.NewStructValidator()

	validateSAML(config, validator)
	require.NotEmpty(t, validator.Errors())
	assert.Contains(t, validator.Errors()[0].Error(), "can't be 'ignore' with option 'certificate'")
}
