// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
)

const errFmtOIDCClientConsentOffline = "identity_providers: oidc: clients: client '%s': option 'consent_implicit_offline_access' "

// validateOIDCClientConsentImplicitOfflineAccess only allows consent_implicit_offline_access for a confidential client
// with the implicit consent mode: the administrator's configuration stands in for the user's consent to offline access
// (OpenID Connect Core 1.0 Section 11), which a public client's identity can't carry.
func validateOIDCClientConsentImplicitOfflineAccess(c int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	client := &config.Clients[c]

	if !client.ConsentImplicitOfflineAccess {
		return
	}

	if client.ConsentMode != oidc.ClientConsentModeImplicit.String() {
		validator.Push(fmt.Errorf(errFmtOIDCClientConsentOffline+"requires the 'consent_mode' to be 'implicit' but it's configured as '%s'", client.ID, client.ConsentMode))
	}

	if client.Public {
		validator.Push(fmt.Errorf(errFmtOIDCClientConsentOffline+"can't be used with a public client", client.ID))
	}
}
