// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto/x509"
	"net/http"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/storage"
	"github.com/authelia/authelia/v4/internal/templates"
)

// NewOpenIDConnectProvider new-ups a OpenIDConnectProvider.
func NewOpenIDConnectProvider(config *schema.Configuration, store storage.Provider, templates *templates.Provider) (provider *OpenIDConnectProvider) {
	if config == nil || config.IdentityProviders.OIDC == nil {
		return nil
	}

	issuer := NewIssuer(config.IdentityProviders.OIDC.JSONWebKeys)

	provider = &OpenIDConnectProvider{
		Store:  NewStore(config, store),
		Issuer: issuer,
		Config: NewConfig(config.IdentityProviders.OIDC, issuer, templates),
	}

	provider.config = provider.Config

	provider.Provider = oauthelia2.New(provider.Store, provider.Config)

	provider.LoadHandlers(provider.Store)

	return provider
}

// WriteDynamicAuthorizeError writes the authorization error appropriate for the given requester.
func (p *OpenIDConnectProvider) WriteDynamicAuthorizeError(ctx Context, rw http.ResponseWriter, requester oauthelia2.Requester, err error) {
	switch r := requester.(type) {
	case oauthelia2.DeviceAuthorizeRequester:
		p.WriteRFC8628UserAuthorizeError(ctx, rw, r, err)
	case oauthelia2.AuthorizeRequester:
		p.WriteAuthorizeError(ctx, rw, r, err)
	}
}

// EnableClientIDMetadataDocuments configures the Client ID Metadata Document support when it's enabled. The trusted
// certificates are those Authelia trusts, which the documents are fetched with.
func (p *OpenIDConnectProvider) EnableClientIDMetadataDocuments(config *schema.Configuration, store storage.Provider, trusted *x509.CertPool) (err error) {
	if p == nil || config == nil || config.IdentityProviders.OIDC == nil {
		return nil
	}

	var policies map[string]ClientAuthorizationPolicy

	if memory, ok := p.ClientStore.(*MemoryClientStore); ok {
		policies = memory.GetAuthorizationPolicies()
	}

	p.ClientIDMetadataDocuments, err = NewClientIDMetadataDocuments(config.IdentityProviders.OIDC, p.Config, store, policies, trusted)

	return err
}
