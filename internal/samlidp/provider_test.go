// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func newTestProvider(t *testing.T, keycloak bool) *Provider {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "idp"}, NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	provider, err := New(&schema.IdentityProvidersSAML{
		Key:                     key,
		CertificateChain:        schema.NewX509CertificateChainFromCerts([]*x509.Certificate{certificate}),
		EnableKeycloakEndpoints: keycloak,
	})
	require.NoError(t, err)

	return provider
}

func TestIdentityProviderEndpoints(t *testing.T) {
	issuer, err := url.Parse("https://id.example.com/realms/test")
	require.NoError(t, err)

	idp := newTestProvider(t, false).IdentityProvider(issuer, nil, nil)
	assert.Equal(t, "https://id.example.com/realms/test/api/saml/sso", idp.SSOURL.String())
	assert.Equal(t, "https://id.example.com/realms/test/api/saml/metadata", idp.MetadataURL.String())
	assert.Equal(t, "https://id.example.com/realms/test", idp.EntityID)

	idp = newTestProvider(t, true).IdentityProvider(issuer, nil, nil)
	assert.Equal(t, "https://id.example.com/realms/test/protocol/saml", idp.SSOURL.String())
	assert.Equal(t, "https://id.example.com/realms/test/protocol/saml/descriptor", idp.MetadataURL.String())
}
