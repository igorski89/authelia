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

	// The exchange evaluates the authorization policies of this client and of the clients in its audience with the
	// address of the client performing the exchange, not of the user, so a networks criterion would apply to every
	// user alike.
	for _, id := range append([]string{client.ID}, client.Audience...) {
		if name, ok := oidcClientAuthorizationPolicyName(config, id); ok && oidcPolicyHasNetworks(config, name) {
			validator.Push(fmt.Errorf(errFmtOIDCClientTokenExchangeNetworks, client.ID, id, name))
		}
	}
}

// validateOIDCClientTokenExchangeSubjectConsent requires the user's consent where a client lets others exchange its
// tokens: the consent screen of that client is the only one the user sees for what the exchange grants.
func validateOIDCClientTokenExchangeSubjectConsent(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	client := &config.Clients[c]

	if len(client.SubjectTokenClientsSupported) != 0 && client.ConsentMode == oidc.ClientConsentModeImplicit.String() {
		validator.Push(fmt.Errorf(errFmtOIDCClientTokenExchangeImplicitConsent, client.ID))
	}
}

func oidcClientAuthorizationPolicyName(config *schema.IdentityProvidersOpenIDConnect, id string) (name string, ok bool) {
	for i := range config.Clients {
		if config.Clients[i].ID == id {
			return config.Clients[i].AuthorizationPolicy, true
		}
	}

	return "", false
}

func oidcPolicyHasNetworks(config *schema.IdentityProvidersOpenIDConnect, name string) bool {
	policy, ok := config.AuthorizationPolicies[name]
	if !ok {
		return false
	}

	for _, rule := range policy.Rules {
		if len(rule.Networks) != 0 {
			return true
		}
	}

	return false
}

const (
	errFmtOIDCClientTokenExchangeExcluded        = "identity_providers: oidc: clients: client '%s': option '%s' must not contain '%s' with the token exchange grant type"
	errFmtOIDCClientTokenExchangeNetworks        = "identity_providers: oidc: clients: client '%s': option 'authorization_policy' of the client '%s' is '%s', which has rules with 'networks', which a token exchange can't evaluate as it sees the address of the client performing it"
	errFmtOIDCClientTokenExchangeImplicitConsent = "identity_providers: oidc: clients: client '%s': option 'consent_mode' must not be 'implicit' with option 'subject_token_clients_supported', as its consent screen is the only one the user sees for the token exchange"
)
