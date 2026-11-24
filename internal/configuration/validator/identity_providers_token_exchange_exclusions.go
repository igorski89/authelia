// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/utils"
)

// validateOIDCClientTokenExchangeExclusions keeps the tokens a client gets from a token exchange short-lived and
// without privileges the person's own login didn't need: such a client may neither have the refresh token grant nor
// the offline, bearer authorization, or administration scopes. An exchanged token is a copy of the person's identity
// for the client, which apps verify themselves, so it is kept as narrow as the person's own token.
func validateOIDCClientTokenExchangeExclusions(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator, te bool) {
	if !te {
		return
	}

	client := &config.Clients[c]

	if utils.IsStringInSlice(oidc.GrantTypeRefreshToken, client.GrantTypes) {
		validator.Push(fmt.Errorf(errFmtOIDCClientTokenExchangeExcluded, client.ID, "grant_types", oidc.GrantTypeRefreshToken))
	}

	for _, scope := range []string{oidc.ScopeOfflineAccess, oidc.ScopeOffline, oidc.ScopeAutheliaBearerAuthz, oidc.ScopeAutheliaAdminRead, oidc.ScopeAutheliaAdminWrite} {
		if utils.IsStringInSlice(scope, client.Scopes) {
			validator.Push(fmt.Errorf(errFmtOIDCClientTokenExchangeExcluded, client.ID, "scopes", scope))
		}
	}
}

const errFmtOIDCClientTokenExchangeExcluded = "identity_providers: oidc: clients: client '%s': option '%s' must not contain '%s' with the token exchange grant type"
