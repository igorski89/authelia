// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"time"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/oidc"
	"github.com/authelia/authelia/v4/internal/utils"
)

const (
	errFmtOIDCCIMD                  = "identity_providers: oidc: client_id_metadata_documents: "
	errFmtOIDCCIMDRule              = errFmtOIDCCIMD + "rules: rule #%d (domain '%s'): "
	errFmtOIDCCIMDNoRules           = errFmtOIDCCIMD + "option 'rules' must have at least one rule when 'enabled' is true"
	errFmtOIDCCIMDGuardDisabled     = errFmtOIDCCIMD + "option 'enabled' can't be true with option 'identity_providers.oidc.special_use_address_guard.disable', as documents would be fetched from any address"
	errFmtOIDCCIMDPositive          = errFmtOIDCCIMD + "option '%s' must be more than 0 but it's configured as '%v'"
	errFmtOIDCCIMDMaxDocumentBytes  = errFmtOIDCCIMD + "option 'max_document_bytes' must be at most %d but it's configured as '%d'"
	errFmtOIDCCIMDMaxCacheLifespan  = errFmtOIDCCIMD + "option 'max_cache_lifespan' must not be less than option 'cache_lifespan'"
	errFmtOIDCCIMDDomainInvalid     = "identity_providers: oidc: client_id_metadata_documents: rules: rule #%d: option 'domain' must be a host name, optionally with a leading dot for its subdomains only, but it's configured as '%s'"
	errFmtOIDCCIMDDomainOverlap     = errFmtOIDCCIMDRule + "option 'domain' overlaps the domain '%s' of another rule, so a host would match both"
	errFmtOIDCCIMDImplicitConsent   = errFmtOIDCCIMDRule + "option 'consent_mode' must not be 'implicit', as the consent screen is where the user sees which host the client is from"
	errFmtOIDCCIMDScopeExcluded     = errFmtOIDCCIMDRule + "option 'scopes' must not contain '%s'"
	errFmtOIDCCIMDAudienceNotClient = errFmtOIDCCIMDRule + "option 'audience' must only contain registered client IDs, but it contains '%s'"
	errFmtOIDCCIMDClient            = errFmtOIDCCIMDRule + "%s"

	cimdMaxDocumentBytesLimit = 64 * 1024
)

// validateOIDCClientIDMetadataDocuments validates the Client ID Metadata Document configuration and builds the client
// every document of a rule starts from. That client is validated like a registered client, so a document client has
// the same defaults and constraints as one.
func validateOIDCClientIDMetadataDocuments(ctx *ValidateCtx, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	cimd := &config.ClientIDMetadataDocuments

	if !cimd.Enabled {
		return
	}

	if len(cimd.Rules) == 0 {
		validator.Push(errors.New(errFmtOIDCCIMDNoRules))
	}

	if config.SpecialUseAddressGuard.Disable {
		validator.Push(errors.New(errFmtOIDCCIMDGuardDisabled))
	}

	validateOIDCClientIDMetadataDocumentsLimits(cimd, validator)

	for i := range cimd.Rules {
		validateOIDCClientIDMetadataDocumentRule(ctx, i, config, validator)
	}

	validateOIDCClientIDMetadataDocumentsOverlap(cimd, validator)
}

func validateOIDCClientIDMetadataDocumentsLimits(cimd *schema.IdentityProvidersOpenIDConnectClientIDMetadataDocuments, validator *schema.StructValidator) {
	for _, d := range []struct {
		name     string
		value    *time.Duration
		fallback time.Duration
	}{
		{"fetch_timeout", &cimd.FetchTimeout, 5 * time.Second},
		{"cache_lifespan", &cimd.CacheLifespan, time.Hour},
		{"max_cache_lifespan", &cimd.MaxCacheLifespan, 24 * time.Hour},
	} {
		switch {
		case *d.value == 0:
			*d.value = d.fallback
		case *d.value < 0:
			validator.Push(fmt.Errorf(errFmtOIDCCIMDPositive, d.name, *d.value))
		}
	}

	if cimd.MaxCacheLifespan > 0 && cimd.CacheLifespan > cimd.MaxCacheLifespan {
		validator.Push(errors.New(errFmtOIDCCIMDMaxCacheLifespan))
	}

	switch {
	case cimd.MaxDocumentBytes == 0:
		cimd.MaxDocumentBytes = 5120
	case cimd.MaxDocumentBytes < 0:
		validator.Push(fmt.Errorf(errFmtOIDCCIMDPositive, "max_document_bytes", cimd.MaxDocumentBytes))
	case cimd.MaxDocumentBytes > cimdMaxDocumentBytesLimit:
		validator.Push(fmt.Errorf(errFmtOIDCCIMDMaxDocumentBytes, cimdMaxDocumentBytesLimit, cimd.MaxDocumentBytes))
	}

	// The count of documents per host is never off: it bounds the memory one host can make the cache use.
	switch {
	case cimd.MaxDocumentsPerHost == 0:
		cimd.MaxDocumentsPerHost = 20
	case cimd.MaxDocumentsPerHost < 0:
		validator.Push(fmt.Errorf(errFmtOIDCCIMDPositive, "max_documents_per_host", cimd.MaxDocumentsPerHost))
	}
}

// IsValidOIDCClientIDMetadataDocumentDomain reports whether domain is a host name with an optional leading dot.
func isValidOIDCClientIDMetadataDocumentDomain(domain string) bool {
	host := strings.TrimPrefix(domain, ".")

	if host == "" || host != strings.ToLower(host) || strings.HasSuffix(host, ".") || strings.Contains(host, "..") {
		return false
	}

	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}

	for _, r := range host {
		if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '.' {
			return false
		}
	}

	return true
}

func validateOIDCClientIDMetadataDocumentRule(ctx *ValidateCtx, i int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) {
	rule := &config.ClientIDMetadataDocuments.Rules[i]

	if !isValidOIDCClientIDMetadataDocumentDomain(rule.Domain) {
		validator.Push(fmt.Errorf(errFmtOIDCCIMDDomainInvalid, i+1, rule.Domain))

		return
	}

	if rule.ConsentMode == "" {
		rule.ConsentMode = oidc.ClientConsentModeExplicit.String()
	} else if rule.ConsentMode == oidc.ClientConsentModeImplicit.String() {
		validator.Push(fmt.Errorf(errFmtOIDCCIMDImplicitConsent, i+1, rule.Domain))
	}

	if len(rule.Scopes) == 0 {
		rule.Scopes = []string{oidc.ScopeOpenID}
	}

	for _, scope := range []string{oidc.ScopeAutheliaBearerAuthz, oidc.ScopeAutheliaAdminRead, oidc.ScopeAutheliaAdminWrite} {
		if utils.IsStringInSlice(scope, rule.Scopes) {
			validator.Push(fmt.Errorf(errFmtOIDCCIMDScopeExcluded, i+1, rule.Domain, scope))
		}
	}

	for _, audience := range rule.Audience {
		if _, ok := oidcClientAuthorizationPolicyName(config, audience); !ok {
			validator.Push(fmt.Errorf(errFmtOIDCCIMDAudienceNotClient, i+1, rule.Domain, audience))
		}
	}

	rule.Client = validateOIDCClientIDMetadataDocumentRuleClient(ctx, i, config, validator)
}

// validateOIDCClientIDMetadataDocumentRuleClient validates the client every document of a rule starts from as if it
// were a registered client, and returns it with its defaults.
func validateOIDCClientIDMetadataDocumentRuleClient(ctx *ValidateCtx, i int, config *schema.IdentityProvidersOpenIDConnect, validator *schema.StructValidator) (client schema.IdentityProvidersOpenIDConnectClient) {
	rule := &config.ClientIDMetadataDocuments.Rules[i]
	host := strings.TrimPrefix(rule.Domain, ".")

	client = schema.IdentityProvidersOpenIDConnectClient{
		ID:                           "https://" + host + "/client-id-metadata-document",
		Name:                         host,
		Public:                       true,
		RedirectURIs:                 []string{"https://" + host + "/callback"},
		Audience:                     rule.Audience,
		Resource:                     rule.Resource,
		Scopes:                       rule.Scopes,
		GrantTypes:                   []string{oidc.GrantTypeAuthorizationCode},
		ResponseTypes:                []string{oidc.ResponseTypeAuthorizationCodeFlow},
		AuthorizationPolicy:          rule.AuthorizationPolicy,
		Lifespan:                     rule.Lifespan,
		ClaimsPolicy:                 rule.ClaimsPolicy,
		RequestedAudienceMode:        rule.RequestedAudienceMode,
		ImplicitAudienceWithResource: rule.ImplicitAudienceWithResource,
		ConsentMode:                  rule.ConsentMode,
		ConsentPreConfiguredDuration: rule.ConsentPreConfiguredDuration,
		RequirePKCE:                  true,
		PKCEChallengeMethod:          oidc.PKCEChallengeMethodSHA256,
		TokenEndpointAuthMethod:      oidc.ClientAuthMethodNone,
		AccessTokenSignedResponseAlg: rule.AccessTokenSignedResponseAlg,
	}

	if utils.IsStringInSlice(oidc.ScopeOfflineAccess, rule.Scopes) || utils.IsStringInSlice(oidc.ScopeOffline, rule.Scopes) {
		client.GrantTypes = append(client.GrantTypes, oidc.GrantTypeRefreshToken)
	}

	for _, id := range rule.SubjectTokenClientsSupported {
		client.SubjectTokenClientsSupported = append(client.SubjectTokenClientsSupported, schema.IdentityProvidersOpenIDConnectClientTokenExchangePolicy{ClientID: id})
	}

	// The client is validated in the place of a registered client, and its errors are reported for the rule.
	scratch := schema.NewStructValidator()
	c := len(config.Clients)

	config.Clients = append(config.Clients, client)
	ctx.cacheSectorIdentifierURIs = map[string][]string{}

	validateOIDCClient(ctx, c, config, scratch, func() {})

	client = config.Clients[c]
	config.Clients = config.Clients[:c]
	ctx.cacheSectorIdentifierURIs = nil

	for _, err := range scratch.Errors() {
		validator.Push(fmt.Errorf(errFmtOIDCCIMDClient, i+1, rule.Domain, err))
	}

	return client
}

// validateOIDCClientIDMetadataDocumentsOverlap refuses two rules which match the same host, so the rule of a host is
// never ambiguous.
func validateOIDCClientIDMetadataDocumentsOverlap(cimd *schema.IdentityProvidersOpenIDConnectClientIDMetadataDocuments, validator *schema.StructValidator) {
	for i, a := range cimd.Rules {
		for _, b := range cimd.Rules[:i] {
			if isValidOIDCClientIDMetadataDocumentDomain(a.Domain) && isValidOIDCClientIDMetadataDocumentDomain(b.Domain) && oidcCIMDDomainsOverlap(a.Domain, b.Domain) {
				validator.Push(fmt.Errorf(errFmtOIDCCIMDDomainOverlap, i+1, a.Domain, b.Domain))
			}
		}
	}
}

// oidcCIMDDomainsOverlap reports whether some host matches both domains: an exact domain matches only itself, and a
// domain with a leading dot matches only the subdomains of the rest.
func oidcCIMDDomainsOverlap(a, b string) bool {
	if a == b {
		return true
	}

	matches := func(pattern, host string) bool {
		if strings.HasPrefix(pattern, ".") {
			return strings.HasSuffix(host, pattern)
		}

		return host == pattern
	}

	sub := func(s string) bool { return strings.HasPrefix(s, ".") }

	switch {
	case !sub(a) && !sub(b):
		return false
	case sub(a) && !sub(b):
		return matches(a, b)
	case !sub(a) && sub(b):
		return matches(b, a)
	default:
		return strings.HasSuffix(a, b) || strings.HasSuffix(b, a)
	}
}
