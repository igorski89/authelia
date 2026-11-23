// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

// SGNL fork: the server path may have several segments (see validator/sgnl_server_path.go). StripPath must strip the
// whole prefix and report it as the base URL, which IssuerURL uses.
func TestSGNLStripPathMultiSegment(t *testing.T) {
	const path = "/realms/example-realm"

	testCases := []struct {
		name        string
		uri         string
		expected    any
		expectedURI string
	}{
		{"ShouldStripDiscovery", "/realms/example-realm/.well-known/openid-configuration", path, "/.well-known/openid-configuration"},
		{"ShouldStripWithQuery", "/realms/example-realm/api/oidc/authorization?client_id=x", path, "/api/oidc/authorization?client_id=x"},
		{"ShouldStripExact", "/realms/example-realm", path, "/"},
		{"ShouldNotStripPartialSegment", "/realms/example-realm2/api/health", nil, "/realms/example-realm2/api/health"},
		{"ShouldNotStripFirstSegmentOnly", "/realms/api/health", nil, "/realms/api/health"},
		{"ShouldNotStripRoot", "/api/health", nil, "/api/health"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := &fasthttp.RequestCtx{}
			ctx.Request.SetRequestURI(tc.uri)

			StripPath(path)(func(_ *fasthttp.RequestCtx) {})(ctx)

			assert.Equal(t, tc.expected, ctx.UserValue(UserValueKeyBaseURL))
			assert.Equal(t, tc.expectedURI, string(ctx.RequestURI()))
		})
	}
}
