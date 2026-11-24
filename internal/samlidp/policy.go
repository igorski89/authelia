// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package samlidp

import (
	"fmt"
	"net/http"
	"slices"

	saml "authelia.com/provider/saml"
)

const (
	nameIDFormatEmail       = "email"
	nameIDFormatUnspecified = "unspecified"

	signResponse  = "response"
	signAssertion = "assertion"
)

// nameIDFormat returns the SAML NameID format of a configured name_id_format.
func nameIDFormat(format string) saml.NameIDFormat {
	switch format {
	case nameIDFormatUnspecified:
		return saml.UnspecifiedNameIDFormat
	default:
		return saml.EmailAddressNameIDFormat
	}
}

// issuancePolicy signs the response, the assertion, or both, as each service provider is configured.
type issuancePolicy struct {
	provider *Provider
}

// Issuance implements saml.IssuancePolicy.
func (p issuancePolicy) Issuance(req saml.IssuanceRequest) (issuance saml.Issuance, err error) {
	issuance = req.Defaults

	if req.ServiceProviderMetadata == nil {
		return issuance, nil
	}

	if sp := p.provider.ServiceProvider(req.ServiceProviderMetadata.EntityID); sp != nil {
		switch sp.Config.Sign {
		case signResponse:
			issuance.Sign = saml.SignResponse
		case signAssertion:
			issuance.Sign = saml.SignAssertion
		default:
			issuance.Sign = saml.SignResponseAndAssertion
		}
	}

	return issuance, nil
}

// assertionMaker refuses a user who is not in a group the service provider allows, with the RequestDenied status, and
// otherwise makes the assertion as the library does.
type assertionMaker struct {
	provider *Provider
}

// MakeAssertion implements saml.AssertionMaker.
func (m assertionMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	if req.ServiceProviderMetadata != nil {
		sp := m.provider.ServiceProvider(req.ServiceProviderMetadata.EntityID)

		if sp == nil {
			return saml.ErrRequestDenied.WithDebug("the service provider is not registered")
		}

		if !sp.hasGroup(session.Groups) {
			return saml.ErrRequestDenied.WithDebug("the user is not in a group the service provider allows")
		}
	}

	return saml.DefaultAssertionMaker{}.MakeAssertion(req, session)
}

// nameIDProvider issues the NameID the service provider is configured for, whatever format the request asks for, as
// Keycloak does when the format is forced: the session carries the value and format chosen for the service provider.
type nameIDProvider struct{}

// NameIDFormats implements saml.NameIDProvider.
func (nameIDProvider) NameIDFormats() []string {
	return []string{string(saml.EmailAddressNameIDFormat), string(saml.UnspecifiedNameIDFormat)}
}

// NameID implements saml.NameIDProvider.
func (nameIDProvider) NameID(_ *http.Request, _ saml.NameIDRequest, session *saml.Session) (*saml.NameID, error) {
	if session.NameID == "" {
		return nil, saml.ErrInvalidNameIDPolicy.WithDebug("the user has no value for the NameID format of the service provider")
	}

	return &saml.NameID{Format: session.NameIDFormat, Value: session.NameID}, nil
}

// attributeReleasePolicy releases the attributes the service provider is configured to receive, and no other.
type attributeReleasePolicy struct {
	provider *Provider
}

// ReleaseAttributes implements saml.AttributeReleasePolicy.
func (p attributeReleasePolicy) ReleaseAttributes(req saml.AttributeReleaseRequest, _ *saml.Session, candidates []saml.Attribute) (released []saml.Attribute, err error) {
	if req.ServiceProviderMetadata == nil {
		return nil, nil
	}

	sp := p.provider.ServiceProvider(req.ServiceProviderMetadata.EntityID)
	if sp == nil {
		return nil, nil
	}

	for _, candidate := range candidates {
		if slices.Contains(sp.Config.Attributes, candidate.Name) {
			released = append(released, candidate)
		}
	}

	return released, nil
}

// nameIDPolicyEnforcer accepts the NameID format the service provider is configured for whatever the request asks for,
// as Keycloak does when the format is forced. SAML Core would answer a request for another format with
// InvalidNameIDPolicy; service providers moved from Keycloak, such as Stripe, rely on the forced format instead.
type nameIDPolicyEnforcer struct{}

// EnforceNameIDPolicy implements saml.NameIDPolicyEnforcer.
func (nameIDPolicyEnforcer) EnforceNameIDPolicy(_ *saml.IdpAuthnRequest, _ *saml.Session) error {
	return nil
}

// Authentication context classes the identity provider asserts, and their strength.
//
//nolint:gosec // These are SAML authentication context class references, not credentials.
const (
	AuthnContextPassword                   = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
	AuthnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	AuthnContextRefedsMFA                  = "https://refeds.org/profile/mfa"
)

// authnContextStrength ranks the classes a service provider may request: the password classes, and the classes which
// stand for more than one factor, which only a two factor session satisfies.
var authnContextStrength = map[string]int{
	AuthnContextPassword:                   1,
	AuthnContextPasswordProtectedTransport: 2,
	AuthnContextRefedsMFA:                  3,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract":     3,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered": 3,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard":                   3,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI":                3,
	"urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken":               3,
	"http://schemas.microsoft.com/claims/multipleauthn":                  3,
}

// authnContextEnforcer refuses a request only when the session is weaker than every class it requests: a session at
// least as strong as a requested class (stronger with the better comparison), or a class it can't rank, is answered,
// as Keycloak answers requests without enforcing the requested context. A service provider which asks for
// PasswordProtectedTransport exactly then still gets the assertion of a two factor session, which states the stronger
// class it really has.
type authnContextEnforcer struct{}

// SatisfiesAuthnContext implements saml.AuthnContextEnforcer.
func (authnContextEnforcer) SatisfiesAuthnContext(requested *saml.RequestedAuthnContext, session *saml.Session) error {
	if requested == nil || len(requested.AuthnContextClassRefs) == 0 {
		return nil
	}

	asserted := session.AuthnContextClassRef
	if asserted == "" {
		asserted = AuthnContextPasswordProtectedTransport
	}

	better := requested.Comparison == saml.AuthnContextComparisonBetter

	for _, class := range requested.AuthnContextClassRefs {
		strength, known := authnContextStrength[class]

		switch {
		case !known:
			return nil
		case better && authnContextStrength[asserted] > strength:
			return nil
		case !better && authnContextStrength[asserted] >= strength:
			return nil
		}
	}

	return fmt.Errorf("the authentication of the session (%s) doesn't satisfy any requested class", asserted)
}
