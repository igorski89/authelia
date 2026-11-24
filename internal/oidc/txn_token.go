// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/rfc8693"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// NewRFC8693TokenTypes builds the token types of the configured RFC8693 token exchange, keyed by their URN. The access
// token type is used when none are configured.
func NewRFC8693TokenTypes(config *schema.IdentityProvidersOpenIDConnectTokenExchange, issuer *Issuer) (types map[string]oauthelia2.RFC8693TokenType) {
	names := config.TokenTypes

	if len(names) == 0 {
		names = []string{TokenTypeAccessToken}
	}

	types = make(map[string]oauthelia2.RFC8693TokenType, len(names))

	for _, name := range names {
		types[name] = &rfc8693.DefaultTokenType{Name: name}
	}

	return types
}

func defaultRequestedTokenType(config *schema.IdentityProvidersOpenIDConnectTokenExchange) string {
	if config.DefaultRequestedTokenType == "" {
		return TokenTypeAccessToken
	}

	return config.DefaultRequestedTokenType
}
