// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"testing"

	"github.com/fasthttp/router"
	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/samlidp"
)

func TestRegisterSAMLRoutes(t *testing.T) {
	for _, keycloak := range []bool{false, true} {
		config := &schema.Configuration{IdentityProviders: schema.IdentityProviders{SAML: &schema.IdentityProvidersSAML{EnableKeycloakEndpoints: keycloak}}}
		r := router.New()

		RegisterSAMLRoutes(r, config, middlewares.Providers{})

		registered := func(method, path string) bool {
			handler, _ := r.Lookup(method, path, &fasthttp.RequestCtx{})

			return handler != nil
		}

		assert.True(t, registered(fasthttp.MethodGet, samlidp.EndpointPathMetadata))
		assert.True(t, registered(fasthttp.MethodGet, samlidp.EndpointPathSSO))
		assert.True(t, registered(fasthttp.MethodPost, samlidp.EndpointPathSSO))
		assert.True(t, registered(fasthttp.MethodGet, samlidp.EndpointPathSSO+"/resume"))

		// Keycloak's paths are only served when enable_keycloak_endpoints is set.
		assert.Equal(t, keycloak, registered(fasthttp.MethodGet, samlidp.EndpointPathKeycloakMetadata))
		assert.Equal(t, keycloak, registered(fasthttp.MethodGet, samlidp.EndpointPathKeycloakSSO))
		assert.Equal(t, keycloak, registered(fasthttp.MethodPost, samlidp.EndpointPathKeycloakSSO))
	}
}
