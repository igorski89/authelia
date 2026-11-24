// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package samlidp is the SAML 2.0 identity provider of Authelia. It configures the identity provider of
// authelia.com/provider/saml for each issuer and provides the service providers registered in the configuration;
// the handlers supply the session of the user.
package samlidp

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"slices"
	"sync"
	"time"

	saml "authelia.com/provider/saml"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

const (
	// EndpointPathMetadata is the path of the metadata of the identity provider under the issuer.
	EndpointPathMetadata = "/api/saml/metadata"

	// EndpointPathSSO is the path of the single sign-on endpoint under the issuer.
	EndpointPathSSO = "/api/saml/sso"

	// EndpointPathKeycloakSSO is Keycloak's path of the single sign-on endpoint of a realm, served when
	// enable_keycloak_endpoints is set.
	EndpointPathKeycloakSSO = "/protocol/saml"

	// EndpointPathKeycloakMetadata is Keycloak's path of the metadata of a realm, served when
	// enable_keycloak_endpoints is set.
	EndpointPathKeycloakMetadata = "/protocol/saml/descriptor"

	// maxAuthnRequestAge allows for a login which takes a while, such as registering a first passkey.
	maxAuthnRequestAge = 15 * time.Minute

	// replayStoreCapacity is the number of request IDs kept for replay detection, one per answered request for
	// maxAuthnRequestAge. The store refuses requests when it is full, so it is several times the library's default; with
	// the rate limit of the single sign-on endpoints one address can only hold a few hundred keys.
	replayStoreCapacity = 4 * saml.DefaultMemoryReplayStoreCapacity

	// MaxRelayStateLength is the longest RelayState accepted. SAML Bindings 3.4.3 limits it to 80 bytes, which
	// several service providers exceed.
	MaxRelayStateLength = 1024

	// MaxRequestLength is the longest encoded SAMLRequest accepted.
	MaxRequestLength = 16 * 1024

	// MaxBodyLength is the largest body of a single sign-on request, as the library allows.
	MaxBodyLength = 128 * 1024

	// MaxStoredRequestLength is the largest pending request kept while the user logs in: the request, the RelayState,
	// and the signature of the HTTP-Redirect binding, encoded.
	MaxStoredRequestLength = 24 * 1024
)

// Provider is the SAML 2.0 identity provider.
type Provider struct {
	config *schema.IdentityProvidersSAML

	signer        crypto.Signer
	certificate   *x509.Certificate
	intermediates []*x509.Certificate

	serviceProviders map[string]*ServiceProvider

	mu   sync.Mutex
	idps map[string]*saml.IdentityProvider

	// replay is shared by the identity providers of every issuer, which bounds its memory.
	replay saml.ReplayStore
}

// ServiceProvider is a registered service provider with its metadata.
type ServiceProvider struct {
	Config   *schema.IdentityProvidersSAMLServiceProvider
	Metadata *saml.EntityDescriptor
}

// New returns the SAML 2.0 identity provider of the configuration.
func New(config *schema.IdentityProvidersSAML) (provider *Provider, err error) {
	if config == nil {
		return nil, nil
	}

	signer, ok := config.Key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("error initializing the SAML identity provider: the key can't sign")
	}

	certificates := config.CertificateChain.Certificates()
	if len(certificates) == 0 {
		return nil, fmt.Errorf("error initializing the SAML identity provider: the certificate chain is empty")
	}

	provider = &Provider{
		config:           config,
		signer:           signer,
		certificate:      certificates[0],
		intermediates:    certificates[1:],
		serviceProviders: make(map[string]*ServiceProvider, len(config.ServiceProviders)),
		idps:             map[string]*saml.IdentityProvider{},
		replay:           saml.NewMemoryReplayStore(replayStoreCapacity),
	}

	for i := range config.ServiceProviders {
		sp := &config.ServiceProviders[i]

		provider.serviceProviders[sp.EntityID] = &ServiceProvider{Config: sp, Metadata: newServiceProviderMetadata(sp)}
	}

	return provider, nil
}

// ServiceProvider returns the registered service provider with the entity ID, or nil.
func (p *Provider) ServiceProvider(entityID string) *ServiceProvider {
	return p.serviceProviders[entityID]
}

// GetServiceProvider implements saml.ServiceProviderProvider.
func (p *Provider) GetServiceProvider(_ *http.Request, serviceProviderID string) (*saml.EntityDescriptor, error) {
	if sp := p.serviceProviders[serviceProviderID]; sp != nil {
		return sp.Metadata, nil
	}

	return nil, os.ErrNotExist
}

// IdentityProvider returns the identity provider of the issuer, which is made once for each issuer, as its entity ID
// and endpoints are derived from it. The session provider and observer are the same for every issuer.
func (p *Provider) IdentityProvider(issuer *url.URL, sessions saml.SessionProvider, observer saml.Observer) *saml.IdentityProvider {
	key := issuer.String()

	p.mu.Lock()
	defer p.mu.Unlock()

	if idp, ok := p.idps[key]; ok {
		return idp
	}

	entityID := p.config.EntityID
	if entityID == "" {
		entityID = key
	}

	ssoPath, metadataPath := EndpointPathSSO, EndpointPathMetadata

	// Service providers configured for Keycloak know these URLs, and check the Destination of the requests against
	// the SSO URL, so they are the URLs the metadata publishes.
	if p.config.EnableKeycloakEndpoints {
		ssoPath, metadataPath = EndpointPathKeycloakSSO, EndpointPathKeycloakMetadata
	}

	idp := &saml.IdentityProvider{
		Key:                     p.signer,
		Signer:                  p.signer,
		Certificate:             p.certificate,
		Intermediates:           p.intermediates,
		EntityID:                entityID,
		MetadataURL:             *issuer.JoinPath(metadataPath),
		SSOURL:                  *issuer.JoinPath(ssoPath),
		ServiceProviderProvider: p,
		SessionProvider:         sessions,
		AssertionMaker:          assertionMaker{provider: p},
		IssuancePolicy:          issuancePolicy{provider: p},
		NameIDProvider:          nameIDProvider{},
		NameIDPolicyEnforcer:    nameIDPolicyEnforcer{},
		AuthnContextEnforcer:    authnContextEnforcer{},
		AttributeReleasePolicy:  attributeReleasePolicy{provider: p},
		AssertionLifetime:       p.config.AssertionLifespan,
		MaxAuthnRequestAge:      maxAuthnRequestAge,
		Observer:                observer,
		ResponseFormTemplate:    responseFormTemplate,
		ReplayStore:             p.replay,
	}

	p.idps[key] = idp

	return idp
}

// newServiceProviderMetadata returns the metadata of a service provider from its configuration.
func newServiceProviderMetadata(config *schema.IdentityProvidersSAMLServiceProvider) *saml.EntityDescriptor {
	signed := config.Certificate.HasCertificates()

	descriptor := saml.SPSSODescriptor{
		SSODescriptor: saml.SSODescriptor{
			RoleDescriptor: saml.RoleDescriptor{
				ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
			},
			NameIDFormats: []saml.NameIDFormat{nameIDFormat(config.NameIDFormat)},
		},
		AuthnRequestsSigned:  &signed,
		WantAssertionsSigned: new(true),
	}

	for i, u := range config.AssertionConsumerServiceURLs {
		descriptor.AssertionConsumerServices = append(descriptor.AssertionConsumerServices, saml.IndexedEndpoint{
			Binding:   saml.HTTPPostBinding,
			Location:  u.String(),
			Index:     i,
			IsDefault: new(i == 0),
		})
	}

	for _, certificate := range config.Certificate.Certificates() {
		descriptor.KeyDescriptors = append(descriptor.KeyDescriptors, saml.KeyDescriptor{
			Use:     "signing",
			KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: encodeCertificate(certificate)}}}},
		})
	}

	return &saml.EntityDescriptor{EntityID: config.EntityID, SPSSODescriptors: []saml.SPSSODescriptor{descriptor}}
}

func encodeCertificate(certificate *x509.Certificate) string {
	return base64.StdEncoding.EncodeToString(certificate.Raw)
}

// ErrNotFound is returned for a request to an issuer or service provider the identity provider doesn't serve.
var ErrNotFound = errors.New("not found")

// hasGroup returns true if the service provider allows any group, or one of the groups of the user.
func (sp *ServiceProvider) hasGroup(groups []string) bool {
	if len(sp.Config.Groups) == 0 {
		return true
	}

	for _, group := range groups {
		if slices.Contains(sp.Config.Groups, group) {
			return true
		}
	}

	return false
}
