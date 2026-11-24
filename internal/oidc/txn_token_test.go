// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"authelia.com/provider/oauth2/handler/rfc8693"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
)

func TestNewRFC8693TokenTypes(t *testing.T) {
	t.Run("ShouldDefaultToStaticTypes", func(t *testing.T) {
		types := oidc.NewRFC8693TokenTypes(&schema.IdentityProvidersOpenIDConnectTokenExchange{}, nil)

		require.Len(t, types, 1)

		for _, name := range []string{oidc.TokenTypeAccessToken} {
			tokenType, ok := types[name].(*rfc8693.DefaultTokenType)

			require.True(t, ok)
			assert.Equal(t, name, tokenType.Name)
		}
	})

	t.Run("ShouldBuildListedStaticTypesOnly", func(t *testing.T) {
		types := oidc.NewRFC8693TokenTypes(&schema.IdentityProvidersOpenIDConnectTokenExchange{
			TokenTypes: []string{oidc.TokenTypeAccessToken},
		}, nil)

		require.Len(t, types, 1)
		assert.Contains(t, types, oidc.TokenTypeAccessToken)
	})
}
