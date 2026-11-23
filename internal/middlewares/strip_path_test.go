// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/valyala/fasthttp"
)

func TestStripPath(t *testing.T) {
	testCases := []struct {
		name        string
		path        string
		uri         string
		expected    string
		expectedRaw string
		expectedURI string
	}{
		{
			"ShouldHandleEmpty",
			"",
			"",
			"",
			"",
			"",
		},
		{
			"ShouldHandleSingleSlash",
			"/",
			"",
			"",
			"",
			"",
		},
		{
			"ShouldHandleAuthPathNoPath",
			"/auth",
			"/",
			"",
			"",
			"/",
		},
		{
			"ShouldHandleAuthPathNoPathQuery",
			"/auth",
			"/?rd=abc",
			"",
			"",
			"/?rd=abc",
		},
		{
			"ShouldHandleAuthPathNoPathQueryNoSlash",
			"/auth",
			"?rd=abc",
			"",
			"",
			"/?rd=abc",
		},
		{
			"ShouldHandleAuthPath",
			"/auth",
			"/auth",
			"/auth",
			"/auth",
			"/",
		},
		{
			"ShouldHandleAuthSubPath",
			"/auth",
			"/auth/example",
			"/auth",
			"/auth/example",
			"/example",
		},
		{
			"ShouldHandleAuthSubPathQuery",
			"/auth",
			"/auth?rd=123",
			"/auth",
			"/auth?rd=123",
			"/?rd=123",
		},
		{
			"ShouldHandleAuthSubPathQueryWithTrailingSlash",
			"/auth",
			"/auth/?rd=123",
			"/auth",
			"/auth/?rd=123",
			"/?rd=123",
		},
		{
			"ShouldHandleShortSubPath",
			"/a",
			"/api/example",
			"",
			"",
			"/api/example",
		},
		{
			"ShouldHandleShortSubPathQuery",
			"/a",
			"/api/example?rd=123",
			"",
			"",
			"/api/example?rd=123",
		},
		{
			"ShouldHandleShortSubPathQueryWithTrailingSlash",
			"/a",
			"/api/example/?rd=123",
			"",
			"",
			"/api/example/?rd=123",
		},
		{
			"ShouldHandleAuthPathNoLeadingSlash",
			"auth",
			"/auth",
			"/auth",
			"/auth",
			"/",
		},
		{
			"ShouldHandleAuthSubPathNoLeadingSlash",
			"auth",
			"/auth/example",
			"/auth",
			"/auth/example",
			"/example",
		},
	}

	nilHandler := func(ctx *fasthttp.RequestCtx) {}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			header := fasthttp.RequestHeader{}

			header.SetRequestURI(tc.uri)

			ctx := &fasthttp.RequestCtx{
				Request: fasthttp.Request{
					Header:                         header, //nolint:govet
					UseHostHeader:                  false,
					DisableRedirectPathNormalizing: false,
				},
			}

			var next fasthttp.RequestHandler

			if tc.path != "" && tc.path != "/" {
				next = nilHandler
			}

			handler := StripPath(tc.path)(next)

			if tc.path == "" || tc.path == "/" {
				assert.Nil(t, handler)

				return
			}

			handler(ctx)

			baseURL := ctx.UserValue(UserValueKeyBaseURL)
			rawURI := ctx.UserValue(UserValueKeyRawURI)

			if tc.expected == "" {
				assert.Nil(t, baseURL)
			} else {
				assert.Equal(t, tc.expected, baseURL)
			}

			if tc.expectedRaw == "" {
				assert.Nil(t, rawURI)
			} else {
				assert.Equal(t, tc.expectedRaw, rawURI)
			}

			assert.Equal(t, tc.expectedURI, string(ctx.RequestURI()))
		})
	}
}

// The server path may have several segments. StripPath must strip the
// whole prefix and report it as the base URL, which IssuerURL uses.
func TestStripPathMultiSegment(t *testing.T) {
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
