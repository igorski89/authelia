// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"time"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/utils"
)

const (
	samlNameIDFormatEmail       = "email"
	samlNameIDFormatUnspecified = "unspecified"

	samlSignBoth      = "both"
	samlSignResponse  = "response"
	samlSignAssertion = "assertion"

	// samlDefaultAssertionLifespan is how long an assertion is valid when no lifespan is configured.
	samlDefaultAssertionLifespan = 5 * time.Minute

	errFmtSAML   = "identity_providers: saml: "
	errFmtSAMLSP = errFmtSAML + "service_providers: service provider '%s': "
)

var (
	validSAMLNameIDFormats         = []string{samlNameIDFormatEmail, samlNameIDFormatUnspecified}
	validSAMLAuthorizationPolicies = []string{policyOneFactor, policyTwoFactor}
	validSAMLSign                  = []string{samlSignBoth, samlSignResponse, samlSignAssertion}
	validSAMLAttributes            = []string{"username", "email", "name", "given_name", "family_name", "groups"}
)

// validateSAML validates the SAML 2.0 identity provider configuration and sets its defaults.
func validateSAML(config *schema.Configuration, validator *schema.StructValidator) {
	saml := config.IdentityProviders.SAML

	if saml == nil {
		return
	}

	switch key := saml.Key.(type) {
	case nil:
		validator.Push(fmt.Errorf(errFmtSAML + "option 'key' is required"))
	case *rsa.PrivateKey:
		if key.N.BitLen() < 2048 {
			validator.Push(fmt.Errorf(errFmtSAML+"option 'key' must be an RSA key of at least 2048 bits but it has %d bits", key.N.BitLen()))
		}
	case *ecdsa.PrivateKey:
		break
	default:
		validator.Push(fmt.Errorf(errFmtSAML+"option 'key' must be an RSA or ECDSA private key but it's a %T", key))
	}

	if !saml.CertificateChain.HasCertificates() {
		validator.Push(fmt.Errorf(errFmtSAML + "option 'certificate_chain' is required"))
	} else if err := saml.CertificateChain.Validate(); err != nil {
		validator.Push(fmt.Errorf(errFmtSAML+"option 'certificate_chain' is not valid: %w", err))
	} else if signer, ok := saml.Key.(crypto.Signer); ok && !saml.CertificateChain.EqualKey(signer) {
		validator.Push(fmt.Errorf(errFmtSAML + "option 'certificate_chain' must be the certificate of option 'key'"))
	}

	switch {
	case saml.AssertionLifespan == 0:
		saml.AssertionLifespan = samlDefaultAssertionLifespan
	case saml.AssertionLifespan < 0:
		validator.Push(fmt.Errorf(errFmtSAML+"option 'assertion_lifespan' must not be negative but it's configured as '%s'", saml.AssertionLifespan))
	}

	if len(saml.ServiceProviders) == 0 {
		validator.Push(fmt.Errorf(errFmtSAML + "option 'service_providers' must have at least one service provider"))
	}

	seen := map[string]bool{}

	for i := range saml.ServiceProviders {
		validateSAMLServiceProvider(&saml.ServiceProviders[i], seen, validator)
	}
}

func validateSAMLServiceProvider(sp *schema.IdentityProvidersSAMLServiceProvider, seen map[string]bool, validator *schema.StructValidator) {
	if sp.EntityID == "" {
		validator.Push(fmt.Errorf(errFmtSAML + "service_providers: option 'entity_id' is required"))

		return
	}

	if seen[sp.EntityID] {
		validator.Push(fmt.Errorf(errFmtSAMLSP+"option 'entity_id' must be unique", sp.EntityID))
	}

	seen[sp.EntityID] = true

	if len(sp.AssertionConsumerServiceURLs) == 0 {
		validator.Push(fmt.Errorf(errFmtSAMLSP+"option 'assertion_consumer_service_urls' must have at least one URL", sp.EntityID))
	}

	for _, u := range sp.AssertionConsumerServiceURLs {
		if u.Scheme != schemeHTTPS || u.Host == "" {
			validator.Push(fmt.Errorf(errFmtSAMLSP+"option 'assertion_consumer_service_urls' must only have absolute https URLs but it has '%s'", sp.EntityID, u.String()))
		}
	}

	if sp.Certificate.HasCertificates() {
		if err := sp.Certificate.Validate(); err != nil {
			validator.Push(fmt.Errorf(errFmtSAMLSP+"option 'certificate' is not valid: %w", sp.EntityID, err))
		}
	}

	sp.NameIDFormat = samlDefault(sp.NameIDFormat, samlNameIDFormatEmail)
	sp.AuthorizationPolicy = samlDefault(sp.AuthorizationPolicy, policyTwoFactor)
	sp.Sign = samlDefault(sp.Sign, samlSignBoth)

	for _, option := range []struct {
		name, value string
		valid       []string
	}{
		{"name_id_format", sp.NameIDFormat, validSAMLNameIDFormats},
		{"authorization_policy", sp.AuthorizationPolicy, validSAMLAuthorizationPolicies},
		{"sign", sp.Sign, validSAMLSign},
	} {
		if !utils.IsStringInSlice(option.value, option.valid) {
			validator.Push(fmt.Errorf(errFmtSAMLSP+"option '%s' must be one of %s but it's configured as '%s'", sp.EntityID, option.name, utils.StringJoinOr(option.valid), option.value))
		}
	}

	for _, attribute := range sp.Attributes {
		if !utils.IsStringInSlice(attribute, validSAMLAttributes) {
			validator.Push(fmt.Errorf(errFmtSAMLSP+"option 'attributes' must only have the values %s but it has '%s'", sp.EntityID, utils.StringJoinAnd(validSAMLAttributes), attribute))
		}
	}
}

func samlDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}

	return value
}
