// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/model"
)

// newClientConsentPolicyOfflineAccess returns the consent policy with the implicit offline access option, which only
// the implicit mode has.
func newClientConsentPolicyOfflineAccess(policy ClientConsentPolicy, enabled bool) ClientConsentPolicy {
	policy.ImplicitOfflineAccess = enabled && policy.Mode == ClientConsentModeImplicit

	return policy
}

// RequesterRequiresExplicitConsentForClient is RequesterRequiresExplicitConsent for the client of the request. A client
// whose consent policy allows implicit offline access (consent_implicit_offline_access) doesn't need explicit consent
// for the offline scopes alone: the administrator's configuration is the condition permitting offline access of OpenID
// Connect Core 1.0 Section 11. Everything else, such as prompt=consent or prompt=login, still requires it, as the
// request is evaluated by RequesterRequiresExplicitConsent without its offline scopes.
func RequesterRequiresExplicitConsentForClient(client Client, requester oauthelia2.Requester) (required bool) {
	if requester == nil || client == nil || !client.GetConsentPolicy().ImplicitOfflineAccess {
		return RequesterRequiresExplicitConsent(requester)
	}

	if ar, ok := requester.(oauthelia2.AuthorizeRequester); ok {
		return RequesterRequiresExplicitConsent(&requesterWithoutOfflineScopes{AuthorizeRequester: ar})
	}

	return RequesterRequiresExplicitConsent(requester)
}

// requesterWithoutOfflineScopes is an authorization request as seen without its offline scopes.
type requesterWithoutOfflineScopes struct {
	oauthelia2.AuthorizeRequester
}

// GetRequestedScopes returns the requested scopes without the offline scopes.
func (r *requesterWithoutOfflineScopes) GetRequestedScopes() oauthelia2.Arguments {
	return withoutOfflineScopes(r.AuthorizeRequester.GetRequestedScopes())
}

// GetGrantedScopes returns the granted scopes without the offline scopes.
func (r *requesterWithoutOfflineScopes) GetGrantedScopes() oauthelia2.Arguments {
	return withoutOfflineScopes(r.AuthorizeRequester.GetGrantedScopes())
}

func withoutOfflineScopes(scopes oauthelia2.Arguments) (out oauthelia2.Arguments) {
	for _, scope := range scopes {
		if scope != ScopeOffline && scope != ScopeOfflineAccess {
			out = append(out, scope)
		}
	}

	return out
}

// ConsentGrantImplicitOfflineAccess grants the requested offline scopes after an implicit consent, which grants every
// other requested scope, when the client's consent policy allows implicit offline access.
func ConsentGrantImplicitOfflineAccess(client Client, consent *model.OAuth2ConsentSession) {
	if client == nil || consent == nil || !client.GetConsentPolicy().ImplicitOfflineAccess {
		return
	}

	for _, scope := range consent.RequestedScopes {
		if scope == ScopeOffline || scope == ScopeOfflineAccess {
			consent.GrantScope(scope)
		}
	}
}
