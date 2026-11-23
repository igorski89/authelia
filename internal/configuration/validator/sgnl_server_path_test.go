// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

func TestSGNLValidateServerPath(t *testing.T) {
	testCases := []struct {
		name     string
		address  string
		expected string
		path     string
	}{
		{"ShouldAllowRoot", "tcp://:9091", "", "/"},
		{"ShouldAllowSingleSegment", "tcp://:9091/auth", "", "/auth"},
		{"ShouldAllowKeycloakRealmPath", "tcp://:9091/realms/example-realm", "", "/realms/example-realm"},
		{"ShouldAllowUnderscoreAndDigits", "tcp://:9091/a_1/b-2/c3", "", "/a_1/b-2/c3"},
		{"ShouldAllowUnicodeLetters", "tcp://:9091/café", "", "/café"},
		{"ShouldRaiseOnTrailingSlash", "tcp://:9091/realms/example/", "server: option 'address' must not have empty path segments or a trailing slash but it's configured as '/realms/example/'", ""},
		{"ShouldRaiseOnEmptySegment", "tcp://:9091/realms//example", "server: option 'address' must not have empty path segments or a trailing slash but it's configured as '/realms//example'", ""},
		{"ShouldRaiseOnDot", "tcp://:9091/realms/ex.ample", "server: option 'address' must have a path with only alphanumeric characters, '-' and '_' in each segment but it's configured as '/realms/ex.ample'", ""},
		{"ShouldRaiseOnRegexpCharacters", "tcp://:9091/realms/ex+ample", "server: option 'address' must have a path with only alphanumeric characters, '-' and '_' in each segment but it's configured as '/realms/ex+ample'", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			validator := schema.NewStructValidator()
			config := &schema.Configuration{
				Server: schema.Server{
					Address: &schema.AddressTCP{Address: MustParseAddress(tc.address)},
				},
			}

			ValidateServer(config, validator)

			if tc.expected == "" {
				assert.Len(t, validator.Errors(), 0)
				assert.Equal(t, tc.path, config.Server.Address.RouterPath())
			} else {
				require.Len(t, validator.Errors(), 1)
				assert.EqualError(t, validator.Errors()[0], tc.expected)
			}
		})
	}
}
