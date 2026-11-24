// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package samlidp

import (
	"testing"

	"github.com/stretchr/testify/assert"

	saml "authelia.com/provider/saml"
)

func TestAuthnContextEnforcer(t *testing.T) {
	mfa := &saml.Session{AuthnContextClassRef: AuthnContextRefedsMFA}
	ppt := &saml.Session{AuthnContextClassRef: AuthnContextPasswordProtectedTransport}

	testCases := []struct {
		name       string
		session    *saml.Session
		class      string
		comparison string
		ok         bool
	}{
		// The case the review found: a two factor session and a service provider asking for a password.
		{"MFASessionPPTExact", mfa, AuthnContextPasswordProtectedTransport, saml.AuthnContextComparisonExact, true},
		{"MFASessionPPTMinimum", mfa, AuthnContextPasswordProtectedTransport, saml.AuthnContextComparisonMinimum, true},
		{"MFASessionMFAExact", mfa, AuthnContextRefedsMFA, "", true},
		{"PPTSessionPPTExact", ppt, AuthnContextPasswordProtectedTransport, "", true},
		{"PPTSessionUnknownClass", ppt, "urn:example:unknown", saml.AuthnContextComparisonExact, true},
		{"PPTSessionMFAMinimum", ppt, AuthnContextRefedsMFA, saml.AuthnContextComparisonMinimum, false},
		{"PPTSessionMFAExact", ppt, AuthnContextRefedsMFA, saml.AuthnContextComparisonExact, false},
		{"DefaultClassIsPPT", &saml.Session{}, AuthnContextRefedsMFA, saml.AuthnContextComparisonMinimum, false},
		{"PPTSessionMobileTwoFactor", ppt, "urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract", saml.AuthnContextComparisonExact, false},
		{"PPTSessionMicrosoftMultipleAuthn", ppt, "http://schemas.microsoft.com/claims/multipleauthn", "", false},
		{"MFASessionSmartcard", mfa, "urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard", saml.AuthnContextComparisonMinimum, true},
		{"PPTSessionBetterThanPPT", ppt, AuthnContextPasswordProtectedTransport, saml.AuthnContextComparisonBetter, false},
		{"MFASessionBetterThanPPT", mfa, AuthnContextPasswordProtectedTransport, saml.AuthnContextComparisonBetter, true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := authnContextEnforcer{}.SatisfiesAuthnContext(&saml.RequestedAuthnContext{Comparison: tc.comparison, AuthnContextClassRefs: []string{tc.class}}, tc.session)

			if tc.ok {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}
