// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-retryablehttp"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/cimd"
	"authelia.com/provider/oauth2/handler/rfc7591"
	"authelia.com/provider/oauth2/token/jwt"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/storage"
)

// ClientIDMetadataDocuments is the Client ID Metadata Document support of the provider: clients identified by the URL
// of a document, from the hosts of the configured rules only.
//
// See: https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-03
type ClientIDMetadataDocuments struct {
	Resolver   oauthelia2.ClientIDMetadataDocumentResolver
	HTTPClient *retryablehttp.Client

	rules    []schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule
	oidc     *schema.IdentityProvidersOpenIDConnect
	policies map[string]ClientAuthorizationPolicy

	cache      *clientIDMetadataDocumentCache
	maxPerHost int
}

// MetadataDocumentClient is a client resolved from a Client ID Metadata Document: a client built from the rule of its
// host, with the redirect URIs, name and scopes of its document.
type MetadataDocumentClient struct {
	*RegisteredClient

	// Host is the host of the client identifier, which the consent screen shows instead of the document's name.
	Host string

	// Loopback is true when the document has a loopback redirect URI, which any process on the user's computer can
	// receive.
	Loopback bool

	permitted []string
}

// IsClientIDMetadataDocumentClient returns true. This implements oauthelia2.ClientIDMetadataDocumentClient.
func (c *MetadataDocumentClient) IsClientIDMetadataDocumentClient() (is bool) {
	return true
}

// GetTokenExchangePermittedClientIDs returns the clients the rule of the host permits to exchange the client's tokens,
// as a document can't permit any. This implements rfc8693.TokenExchangePermittedClientsClient.
func (c *MetadataDocumentClient) GetTokenExchangePermittedClientIDs() (ids []string) {
	return c.permitted
}

// GetConsentResponseBody returns the consent response body of the client, which also names the host of its document
// and whether it returns to the user's computer.
func (c *MetadataDocumentClient) GetConsentResponseBody(session RequesterFormSession, form url.Values, authTime time.Time, disablePreConf bool) (body ConsentGetResponseBody) {
	body = c.RegisteredClient.GetConsentResponseBody(session, form, authTime, disablePreConf)

	body.MetadataDocumentHost = c.Host
	body.Loopback = c.Loopback

	return body
}

// NewClientIDMetadataDocuments returns the Client ID Metadata Document support, or nil when it's not enabled.
func NewClientIDMetadataDocuments(config *schema.IdentityProvidersOpenIDConnect, oidc *Config, store storage.Provider, policies map[string]ClientAuthorizationPolicy, trusted *x509.CertPool) (documents *ClientIDMetadataDocuments, err error) {
	if config == nil || !config.ClientIDMetadataDocuments.Enabled {
		return nil, nil
	}

	settings := config.ClientIDMetadataDocuments

	documents = &ClientIDMetadataDocuments{
		rules:      settings.Rules,
		oidc:       config,
		policies:   policies,
		cache:      newClientIDMetadataDocumentCache(store),
		maxPerHost: settings.MaxDocumentsPerHost,
	}

	if documents.HTTPClient, err = newClientIDMetadataDocumentHTTPClient(settings, trusted); err != nil {
		return nil, err
	}

	var scopes []string

	for _, rule := range settings.Rules {
		for _, scope := range rule.Scopes {
			if !slices.Contains(scopes, scope) {
				scopes = append(scopes, scope)
			}
		}
	}

	if documents.Resolver, err = cimd.NewResolver(cimd.Config{
		Storage:                  documents.cache,
		HTTPClient:               documents.HTTPClient,
		Policy:                   documents.policy,
		Validators:               []oauthelia2.ClientRegistrationValidator{rfc7591.NewLocalMetadataDocumentValidator(oidc), cimd.RedirectURISameOriginValidator{}},
		ValidatorConfig:          oidc,
		Strategy:                 documents,
		Filter:                   documents,
		Scopes:                   scopes,
		GrantTypes:               []string{GrantTypeAuthorizationCode, GrantTypeRefreshToken},
		ResponseTypes:            []string{ResponseTypeAuthorizationCodeFlow},
		TokenEndpointAuthMethods: []string{ClientAuthMethodNone},
		FetchTimeout:             settings.FetchTimeout,
		MaxBodyBytes:             int64(settings.MaxDocumentBytes),
		DefaultLifespan:          settings.CacheLifespan,
		MaxLifespan:              settings.MaxCacheLifespan,
		MaxDocumentsPerDomain:    settings.MaxDocumentsPerDomain,
	}); err != nil {
		return nil, fmt.Errorf("error configuring client id metadata documents: %w", err)
	}

	return documents, nil
}

// Domains returns the domains of the rules, for the library's own check of the host.
func (d *ClientIDMetadataDocuments) Domains() (domains []string) {
	for _, rule := range d.rules {
		domains = append(domains, rule.Domain)
	}

	return domains
}

// Rule returns the rule of the host: the rule of the host itself, or of a domain with a leading dot whose subdomain it
// is. The validator refuses rules which match the same host.
func (d *ClientIDMetadataDocuments) Rule(host string) (rule *schema.IdentityProvidersOpenIDConnectClientIDMetadataDocumentRule) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")

	for i := range d.rules {
		domain := d.rules[i].Domain

		if strings.HasPrefix(domain, ".") {
			if strings.HasSuffix(host, domain) && len(host) > len(domain) {
				return &d.rules[i]
			}
		} else if host == domain {
			return &d.rules[i]
		}
	}

	return nil
}

// policy refuses a client identifier before the cache is read or the document fetched: one whose host has no rule, one
// spelled other than in lower case without a trailing dot (which would be another client of the same host), one with a
// port the rule doesn't list, and a new one of a host which has as many documents cached as it may.
func (d *ClientIDMetadataDocuments) policy(_ context.Context, id *url.URL) (err error) {
	log := logging.Logger().WithField("client_id", id.String())

	if len(id.String()) > 255 {
		log.Warn("Client ID Metadata Document refused: the client identifier is too long")

		return oauthelia2.ErrInvalidClient.WithHint("The client identifier is too long.")
	}

	if id.Host != strings.ToLower(id.Host) || strings.HasSuffix(id.Hostname(), ".") {
		log.Warn("Client ID Metadata Document refused: the host isn't spelled in lower case without a trailing dot")

		return oauthelia2.ErrInvalidClient.WithHint("The host of the client identifier must be in lower case without a trailing dot.")
	}

	rule := d.Rule(id.Hostname())
	if rule == nil {
		log.WithField("host", id.Hostname()).Warn("Client ID Metadata Document refused: no rule permits the host")

		return oauthelia2.ErrInvalidClient.WithHintf("The host '%s' is not permitted to identify clients.", id.Hostname())
	}

	if port := id.Port(); port != "" && !slices.ContainsFunc(rule.Ports, func(p int) bool { return strconv.Itoa(p) == port }) {
		log.Warn("Client ID Metadata Document refused: the rule of the host doesn't permit its port")

		return oauthelia2.ErrInvalidClient.WithHintf("The port '%s' is not permitted to identify clients.", port)
	}

	if d.cache != nil && d.maxPerHost > 0 && !d.cache.Has(id.String()) && d.cache.CountHost(id.Host) >= d.maxPerHost {
		log.Warn("Client ID Metadata Document refused: its host has as many documents cached as it may")

		return oauthelia2.ErrInvalidClient.WithHint("The host has too many clients.")
	}

	return nil
}

// NewClient builds the client of a validated document from the rule of its host. This implements cimd.ClientStrategy.
func (d *ClientIDMetadataDocuments) NewClient(_ context.Context, record *oauthelia2.ClientIDMetadataDocumentRecord) (client oauthelia2.Client, err error) {
	var parsed *url.URL

	if parsed, err = url.Parse(record.ID); err != nil {
		return nil, oauthelia2.ErrInvalidClient.WithWrap(err)
	}

	rule := d.Rule(parsed.Hostname())
	if rule == nil {
		return nil, oauthelia2.ErrInvalidClient.WithHintf("The host '%s' is not permitted to identify clients.", parsed.Hostname())
	}

	metadata := record.Metadata
	if metadata == nil {
		return nil, oauthelia2.ErrInvalidClient.WithHint("The Client ID Metadata Document is empty.")
	}

	config := copyClientIDMetadataDocumentRuleClient(rule.Client)

	config.ID = record.ID
	config.Name = parsed.Host
	config.RedirectURIs = slices.Clone(metadata.RedirectURIs)

	loopback := false

	for _, raw := range config.RedirectURIs {
		if u, err := url.Parse(raw); err == nil && oauthelia2.IsLocalhost(u) {
			loopback = true
		}
	}

	if loopback && !rule.AllowLoopbackRedirectURIs {
		logging.Logger().WithField("client_id", record.ID).Warn("Client ID Metadata Document refused: it has a loopback redirect URI, which the rule of its host doesn't allow")

		return nil, oauthelia2.ErrInvalidClient.WithHint("The client's redirect URIs return to the user's computer, which this host isn't permitted to do.")
	}

	// A native client may use a loopback redirect URI on any port (RFC 8252 Section 7.3); any other redirect URI must
	// match the document exactly.
	if loopback {
		config.ApplicationType = "native"
	} else {
		config.ApplicationType = "web"
	}

	// The document can only narrow the scopes of the rule. A document without a scope has the scopes of the rule.
	if requested := strings.Fields(metadata.Scope); len(requested) != 0 {
		config.Scopes = slices.DeleteFunc(config.Scopes, func(scope string) bool { return !slices.Contains(requested, scope) })
	}

	if len(metadata.GrantTypes) != 0 {
		config.GrantTypes = slices.DeleteFunc(config.GrantTypes, func(grant string) bool { return !slices.Contains(metadata.GrantTypes, grant) })
	}

	registered, ok := NewClient(config, d.oidc, d.policies).(*RegisteredClient)
	if !ok {
		return nil, oauthelia2.ErrServerError.WithDebug("The client of a Client ID Metadata Document isn't a registered client.")
	}

	return &MetadataDocumentClient{RegisteredClient: registered, Host: parsed.Host, Loopback: loopback, permitted: slices.Clone(rule.SubjectTokenClientsSupported)}, nil
}

// FilterClientRegistrationMetadata drops the 'http://localhost' redirect URIs of a 'native' document whose rule permits
// loopback redirect URIs, before the library validates it. Several apps list 'http://localhost/callback' beside
// 'http://127.0.0.1/callback' and send the latter, and the library refuses the whole document for a 'localhost'
// redirect URI (RFC 8252 Section 8.3). The redirect URIs left must match as before, so a client which sends a
// 'localhost' redirect URI is refused at the authorization endpoint. A document left without a redirect URI is
// refused. This implements oauthelia2.ClientRegistrationMetadataStrategy.
func (d *ClientIDMetadataDocuments) FilterClientRegistrationMetadata(_ context.Context, _ oauthelia2.Client, metadata *oauthelia2.ClientRegistrationMetadata) (err error) {
	if metadata == nil || metadata.ApplicationType != ApplicationTypeNative {
		return nil
	}

	id, _ := metadata.Extra[ClaimClientIdentifier].(string)

	parsed, err := url.Parse(id)
	if err != nil {
		return nil
	}

	if rule := d.Rule(parsed.Hostname()); rule == nil || !rule.AllowLoopbackRedirectURIs {
		return nil
	}

	redirects := slices.DeleteFunc(slices.Clone(metadata.RedirectURIs), func(raw string) bool {
		u, perr := url.Parse(raw)

		return perr == nil && u.Scheme == "http" && strings.EqualFold(u.Hostname(), "localhost")
	})

	if len(redirects) == len(metadata.RedirectURIs) {
		return nil
	}

	if len(redirects) == 0 {
		return oauthelia2.ErrInvalidClientMetadata.WithHint("The client's only redirect URIs are on 'localhost', which isn't supported; use the loopback address '127.0.0.1'.")
	}

	logging.Logger().WithFields(map[string]any{"client_id": id, "redirect_uris": redirects}).Debug("Client ID Metadata Document: its 'localhost' redirect URIs are ignored")

	metadata.RedirectURIs = redirects

	return nil
}

func copyClientIDMetadataDocumentRuleClient(client schema.IdentityProvidersOpenIDConnectClient) schema.IdentityProvidersOpenIDConnectClient {
	client.Audience = slices.Clone(client.Audience)
	client.Resource = slices.Clone(client.Resource)
	client.Scopes = slices.Clone(client.Scopes)
	client.GrantTypes = slices.Clone(client.GrantTypes)
	client.ResponseTypes = slices.Clone(client.ResponseTypes)
	client.ResponseModes = slices.Clone(client.ResponseModes)
	client.SubjectTokenClientsSupported = slices.Clone(client.SubjectTokenClientsSupported)

	return client
}

// newClientIDMetadataDocumentHTTPClient returns the client which fetches documents: it trusts the certificates
// Authelia trusts, refuses special-use addresses other than the allowed networks of the guard, doesn't follow
// redirects or retry, and logs each fetch without its body.
func newClientIDMetadataDocumentHTTPClient(settings schema.IdentityProvidersOpenIDConnectClientIDMetadataDocuments, trusted *x509.CertPool) (client *retryablehttp.Client, err error) {
	timeout := settings.FetchTimeout

	base := &retryablehttp.Client{
		HTTPClient: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:       &tls.Config{RootCAs: trusted, MinVersion: tls.VersionTLS12},
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          16,
				MaxConnsPerHost:       4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   timeout,
				ResponseHeaderTimeout: timeout,
			},
			Timeout: timeout,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
		RetryMax:     0,
		CheckRetry:   retryablehttp.DefaultRetryPolicy,
		Backoff:      retryablehttp.DefaultBackoff,
		ErrorHandler: retryablehttp.PassthroughErrorHandler,
	}

	if client, err = oauthelia2.GuardHTTPClient(base, oauthelia2.WithSpecialUseAddressGuardAllowedNetworks(settings.AllowedNetworks...)); err != nil {
		return nil, fmt.Errorf("error configuring the client id metadata document http client: %w", err)
	}

	client.Logger = nil
	client.HTTPClient.Transport = &clientIDMetadataDocumentLoggingTransport{next: client.HTTPClient.Transport}

	return client, nil
}

// clientIDMetadataDocumentLoggingTransport logs every document fetch: the host, path, status and duration, never the
// body.
type clientIDMetadataDocumentLoggingTransport struct {
	next http.RoundTripper
}

func (t *clientIDMetadataDocumentLoggingTransport) RoundTrip(r *http.Request) (response *http.Response, err error) {
	start := time.Now()

	response, err = t.next.RoundTrip(r)

	entry := logging.Logger().WithFields(map[string]any{"host": r.URL.Host, "path": r.URL.Path, "duration": time.Since(start).String()})

	if err != nil {
		entry.WithError(err).Warn("Client ID Metadata Document fetch failed")
	} else {
		entry.WithField("status", response.StatusCode).Info("Client ID Metadata Document fetched")
	}

	return response, err
}

// clientIDMetadataDocumentCache keeps validated documents in memory, bounded by the library's count of documents per
// domain and pruned when they expire. Nothing is persisted: after a restart a document is fetched again when it's
// needed.
type clientIDMetadataDocumentCache struct {
	mu      sync.Mutex
	records map[string][]byte
	domains map[string]string
	expires map[string]time.Time

	store storage.Provider
}

func newClientIDMetadataDocumentCache(store storage.Provider) *clientIDMetadataDocumentCache {
	return &clientIDMetadataDocumentCache{records: map[string][]byte{}, domains: map[string]string{}, expires: map[string]time.Time{}, store: store}
}

// Has reports whether the cache has the record for id.
func (c *clientIDMetadataDocumentCache) Has(id string) (has bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	_, has = c.records[id]

	return has
}

// CountHost returns the number of unexpired records whose client identifier has the host (with its port), unlike the
// library's count, which is of a registrable domain.
func (c *clientIDMetadataDocumentCache) CountHost(host string) (count int) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()

	for id := range c.records {
		// An expired record doesn't count, as the library only prunes records on a resolution the cap would refuse.
		if expires := c.expires[id]; !expires.IsZero() && !expires.After(now) {
			continue
		}

		if u, err := url.Parse(id); err == nil && u.Host == host {
			count++
		}
	}

	return count
}

// GetClientIDMetadataDocument returns a copy of the record for id.
func (c *clientIDMetadataDocumentCache) GetClientIDMetadataDocument(_ context.Context, id string) (record *oauthelia2.ClientIDMetadataDocumentRecord, err error) {
	c.mu.Lock()
	raw, ok := c.records[id]
	c.mu.Unlock()

	if !ok {
		logging.Logger().WithField("client_id", id).Debug("Client ID Metadata Document cache miss")

		return nil, oauthelia2.ErrNotFound
	}

	record = &oauthelia2.ClientIDMetadataDocumentRecord{}

	if err = json.Unmarshal(raw, record); err != nil {
		return nil, err
	}

	logging.Logger().WithField("client_id", id).Debug("Client ID Metadata Document cache hit")

	return record, nil
}

// SetClientIDMetadataDocument stores a copy of the record.
func (c *clientIDMetadataDocumentCache) SetClientIDMetadataDocument(_ context.Context, record *oauthelia2.ClientIDMetadataDocumentRecord) (err error) {
	if record == nil {
		return errors.New("the record is nil")
	}

	var raw []byte

	if raw, err = json.Marshal(record); err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.records[record.ID] = raw
	c.domains[record.ID] = record.Domain
	c.expires[record.ID] = record.ExpiresAt

	return nil
}

// DeleteClientIDMetadataDocument removes the record for id.
func (c *clientIDMetadataDocumentCache) DeleteClientIDMetadataDocument(_ context.Context, id string) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	delete(c.records, id)
	delete(c.domains, id)
	delete(c.expires, id)

	return nil
}

// DeleteExpiredClientIDMetadataDocuments removes the records which expired before the given time.
func (c *clientIDMetadataDocumentCache) DeleteExpiredClientIDMetadataDocuments(_ context.Context, before time.Time) (err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for id, expires := range c.expires {
		if expires.Before(before) {
			delete(c.records, id)
			delete(c.domains, id)
			delete(c.expires, id)
		}
	}

	return nil
}

// RevokeClientIDMetadataDocumentRefreshTokens revokes the refresh tokens of the client, whose document now names
// another client.
func (c *clientIDMetadataDocumentCache) RevokeClientIDMetadataDocumentRefreshTokens(ctx context.Context, id string) (err error) {
	revoked, err := c.store.RevokeOAuth2RefreshTokensByClientID(ctx, id)

	logging.Logger().WithFields(map[string]any{"client_id": id, "revoked": revoked}).Warn("Client ID Metadata Document names another client: its refresh tokens were revoked")

	return err
}

// CountClientIDMetadataDocuments returns the number of records of the domain.
func (c *clientIDMetadataDocumentCache) CountClientIDMetadataDocuments(_ context.Context, domain string) (count int, err error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	for _, d := range c.domains {
		if d == domain {
			count++
		}
	}

	return count, nil
}

// GetResolvedClient returns the registered client with the id or, when Client ID Metadata Documents are enabled and
// the id is the URL of one on a permitted host, the client its document describes.
func (p *OpenIDConnectProvider) GetResolvedClient(ctx context.Context, id string) (client Client, err error) {
	if client, err = p.GetRegisteredClient(ctx, id); err == nil {
		return client, nil
	}

	if p.Config == nil || p.ClientIDMetadataDocuments == nil {
		return nil, err
	}

	var resolved oauthelia2.Client

	if resolved, err = oauthelia2.GetClient(ctx, p.Config, p.Store, id); err != nil {
		logging.Logger().WithField("client_id", id).WithError(err).Debug("Client could not be resolved")

		return nil, err
	}

	if client, ok := resolved.(Client); ok {
		return client, nil
	}

	return nil, oauthelia2.ErrInvalidClient.WithDebugf("The client '%s' is not an Authelia client.", id)
}

// GetClientIDMetadataDocumentResolver returns the resolver, or nil when Client ID Metadata Documents aren't enabled.
// This implements oauthelia2.ClientIDMetadataDocumentConfigProvider.
func (c *Config) GetClientIDMetadataDocumentResolver(_ context.Context) (resolver oauthelia2.ClientIDMetadataDocumentResolver) {
	if c.ClientIDMetadataDocuments == nil {
		return nil
	}

	return c.ClientIDMetadataDocuments.Resolver
}

// GetClientIDMetadataDocumentHTTPClient returns the HTTP client which fetches documents.
func (c *Config) GetClientIDMetadataDocumentHTTPClient(_ context.Context) (client *retryablehttp.Client) {
	if c.ClientIDMetadataDocuments == nil {
		return nil
	}

	return c.ClientIDMetadataDocuments.HTTPClient
}

// GetClientIDMetadataDocumentJWKSFetcherStrategy returns nil: a document client is public, so no 'jwks_uri' is
// fetched.
func (c *Config) GetClientIDMetadataDocumentJWKSFetcherStrategy(_ context.Context) (strategy jwt.JWKSFetcherStrategy) {
	return nil
}

// GetClientIDMetadataDocumentAllowedDomainSuffixes returns the domains of the rules. The library matches a suffix and
// its subdomains, and the rules are matched exactly by the resolver's policy before anything is read or fetched.
func (c *Config) GetClientIDMetadataDocumentAllowedDomainSuffixes(_ context.Context) (suffixes []string) {
	if c.ClientIDMetadataDocuments == nil {
		return nil
	}

	return c.ClientIDMetadataDocuments.Domains()
}

var (
	_ oauthelia2.ClientIDMetadataDocumentClient         = (*MetadataDocumentClient)(nil)
	_ oauthelia2.ClientIDMetadataDocumentConfigProvider = (*Config)(nil)
	_ oauthelia2.ClientIDMetadataDocumentStorage        = (*clientIDMetadataDocumentCache)(nil)
	_ cimd.ClientStrategy                               = (*ClientIDMetadataDocuments)(nil)
)
