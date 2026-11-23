// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/random"
)

func TestNewProvider(t *testing.T) {
	config := &schema.Configuration{
		Session: schema.Session{
			Secret: testSecret,
			Cookies: []schema.SessionCookie{
				{
					SessionCookieCommon: schema.SessionCookieCommon{Name: testName, SameSite: "lax", Expiration: testExpiration},
					Domain:              testDomain,
				},
				{
					SessionCookieCommon: schema.SessionCookieCommon{Name: "other_session", SameSite: "strict", Expiration: testExpiration},
					Domain:              "example.org",
				},
			},
		},
	}

	provider, err := NewProvider(config, []byte(testHMACKey), clock.New(), random.NewMathematical(), newTestRepository())

	require.NoError(t, err)
	require.NotNil(t, provider)

	testCases := []struct {
		name     string
		domain   string
		expected string
		err      string
	}{
		{"ShouldReturnStrategyForFirstDomain", testDomain, testName, ""},
		{"ShouldReturnStrategyForSecondDomain", "example.org", "other_session", ""},
		{"ShouldReturnErrorForUnknownDomain", "example.net", "", "not found"},
		{"ShouldReturnErrorForSubdomainOfConfiguredDomain", "sub.example.com", "", "not found"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			strategy, err := provider.GetStrategy(tc.domain)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, strategy)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, strategy)

			assert.Equal(t, tc.domain, strategy.GetConfig().Domain)
			assert.Equal(t, tc.expected, strategy.GetConfig().Name)
		})
	}
}

func TestDefaultProvider_StartupCheck(t *testing.T) {
	provider, err := NewProvider(&schema.Configuration{Session: schema.Session{Secret: testSecret}}, []byte(testHMACKey), clock.New(), random.NewMathematical(), newTestRepository())

	require.NoError(t, err)

	defaultProvider, ok := provider.(*DefaultProvider)
	require.True(t, ok)

	assert.NoError(t, defaultProvider.StartupCheck())

	_, err = defaultProvider.GetStrategy(testDomain)
	assert.EqualError(t, err, "not found")
}

func TestDefaultProviderCountAndDestroyByUsername(t *testing.T) {
	config := &schema.Configuration{
		Session: schema.Session{
			Secret: testSecret,
			Cookies: []schema.SessionCookie{
				{SessionCookieCommon: schema.SessionCookieCommon{Name: testName, SameSite: "lax", Expiration: testExpiration}, Domain: testDomain},
				{SessionCookieCommon: schema.SessionCookieCommon{Name: "other_session", SameSite: "lax", Expiration: testExpiration}, Domain: "example.org"},
			},
		},
	}

	repository := newTestRepository()

	provider, err := NewProvider(config, []byte(testHMACKey), clock.New(), random.NewMathematical(), repository)
	require.NoError(t, err)

	ctx := context.Background()

	for i, s := range []struct{ domain, username string }{{testDomain, "john"}, {testDomain, "john"}, {"example.org", "john"}, {testDomain, "jane"}} {
		strategy, err := provider.GetStrategy(s.domain)
		require.NoError(t, err)

		issuer, err := issuerOf(s.domain, strategy)
		require.NoError(t, err)

		require.NoError(t, repository.Save(ctx, issuer, fmt.Sprintf("id-%d", i), fmt.Sprintf("pid-%d", i), s.username, time.Hour, []byte("data")))
	}

	count, err := provider.CountByUsername(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, 3, count)

	destroyed, err := provider.DestroyByUsername(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, 3, destroyed)

	count, err = provider.CountByUsername(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	count, err = provider.CountByUsername(ctx, "jane")
	require.NoError(t, err)
	assert.Equal(t, 1, count, "other users keep their sessions")

	_, err = issuerOf("example.net", nil)
	assert.EqualError(t, err, "error resolving the session issuer of cookie domain 'example.net': unsupported strategy <nil>")
}
