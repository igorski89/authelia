// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/model"
)

func newConsentOfflineRequestGranted(granted ...string) *oauthelia2.AuthorizeRequest {
	request := newConsentOfflineRequest("", ScopeOpenID)
	request.GrantedScope = granted

	return request
}

func newConsentOfflineRequest(prompt string, requested ...string) *oauthelia2.AuthorizeRequest {
	form := url.Values{}

	if prompt != "" {
		form.Set(FormParameterPrompt, prompt)
	}

	return &oauthelia2.AuthorizeRequest{
		ResponseTypes: oauthelia2.Arguments{ResponseTypeAuthorizationCodeFlow},
		Request: oauthelia2.Request{
			Form:           form,
			RequestedScope: requested,
		},
	}
}

func TestRequesterRequiresExplicitConsentForClient(t *testing.T) {
	without := &RegisteredClient{ConsentPolicy: newClientConsentPolicyOfflineAccess(ClientConsentPolicy{Mode: ClientConsentModeImplicit}, false)}
	with := &RegisteredClient{ConsentPolicy: newClientConsentPolicyOfflineAccess(ClientConsentPolicy{Mode: ClientConsentModeImplicit}, true)}

	requests := map[string]*oauthelia2.AuthorizeRequest{
		"None":                 newConsentOfflineRequest("", ScopeOpenID),
		"OfflineAccess":        newConsentOfflineRequest("", ScopeOpenID, ScopeOfflineAccess),
		"Offline":              newConsentOfflineRequest("", ScopeOpenID, ScopeOffline),
		"OfflineGranted":       newConsentOfflineRequestGranted(ScopeOfflineAccess),
		"PromptConsent":        newConsentOfflineRequest(PromptConsent, ScopeOpenID, ScopeOfflineAccess),
		"PromptLogin":          newConsentOfflineRequest(PromptLogin, ScopeOpenID, ScopeOfflineAccess),
		"BearerAuthz":          newConsentOfflineRequest("", ScopeAutheliaBearerAuthz, ScopeOfflineAccess),
		"PromptConsentNoScope": newConsentOfflineRequest(PromptConsent, ScopeOpenID),
	}

	// Without the option the client is evaluated exactly as upstream evaluates the request.
	for name, request := range requests {
		assert.Equal(t, RequesterRequiresExplicitConsent(request), RequesterRequiresExplicitConsentForClient(without, request), name)
	}

	// With the option only the offline scopes stop requiring it: the result is upstream's for the same request without
	// them, so a rule upstream adds later applies here too.
	expected := map[string]bool{
		"None": false, "OfflineAccess": false, "Offline": false, "OfflineGranted": false,
		"PromptConsent": true, "PromptLogin": true, "BearerAuthz": true, "PromptConsentNoScope": true,
	}

	for name, request := range requests {
		assert.Equal(t, expected[name], RequesterRequiresExplicitConsentForClient(with, request), name)
	}

	assert.False(t, newClientConsentPolicyOfflineAccess(ClientConsentPolicy{Mode: ClientConsentModePreConfigured}, true).ImplicitOfflineAccess)
}

func TestConsentGrantImplicitOfflineAccess(t *testing.T) {
	with := &RegisteredClient{ConsentPolicy: newClientConsentPolicyOfflineAccess(ClientConsentPolicy{Mode: ClientConsentModeImplicit}, true)}
	without := &RegisteredClient{ConsentPolicy: ClientConsentPolicy{Mode: ClientConsentModeImplicit}}

	consent := &model.OAuth2ConsentSession{RequestedScopes: []string{ScopeOpenID, ScopeOfflineAccess}}
	ConsentGrantImplicit(consent, nil, consent.Subject.UUID, consent.RequestedAt)
	ConsentGrantImplicitOfflineAccess(without, consent)
	assert.NotContains(t, []string(consent.GrantedScopes), ScopeOfflineAccess)

	ConsentGrantImplicitOfflineAccess(with, consent)
	assert.Contains(t, []string(consent.GrantedScopes), ScopeOfflineAccess)
}
