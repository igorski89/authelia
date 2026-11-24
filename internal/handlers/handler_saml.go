// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	saml "authelia.com/provider/saml"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/authorization"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/samlidp"
	"github.com/authelia/authelia/v4/internal/session"
)

const (
	flowNameSAML = "saml"

	// samlFlowLifespan is how long a SAML authentication request waits for the user to log in.
	samlFlowLifespan = 15 * time.Minute

	// samlEndpointPathResume is where the portal sends the user back to once logged in, to resume the request.
	samlEndpointPathResume = "/api/saml/sso/resume"

	// samlRefedsMFA is the authentication context class of a session with two factors.
	samlRefedsMFA = samlidp.AuthnContextRefedsMFA
)

type ctxKeySAMLAutheliaCtx struct{}

// samlClientAddressNone isn't an IP address, so assertions state no client address.
const samlClientAddressNone = "none"

// ctxKeySAMLFlowCreatedAt carries the time the flow of a resumed request was created, which a forced authentication
// must be later than.
type ctxKeySAMLFlowCreatedAt struct{}

// ctxKeySAMLResumed marks a request resumed after login. Its session was judged sufficient before, so an insufficient
// one gets an error rather than another trip through the portal, which could loop.
type ctxKeySAMLResumed struct{}

// SAMLMetadataGET serves the metadata of the SAML 2.0 identity provider.
func SAMLMetadataGET(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request) {
	idp, ok := samlIdentityProvider(ctx, rw)
	if !ok {
		return
	}

	idp.ServeMetadata(rw, r)
}

// SAMLSSO serves the SAML 2.0 single sign-on endpoint with the HTTP-Redirect and HTTP-POST bindings.
func SAMLSSO(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request) {
	idp, ok := samlIdentityProvider(ctx, rw)
	if !ok {
		return
	}

	// Only a request which keeps a pending request counts against the rate limit (samlLoginRedirect), so a page which
	// makes browsers send requests can't use up the limit of their address for users who are logged in.
	ctx.SetUserValue(middlewares.UserValueRateLimitExempt, true)

	// A pending request is kept for each anonymous request, so its size is bounded before anything else: the body, as
	// the form is only parsed once, and every field the library takes a request from, including the SAMLRedirectQuery
	// of an HTTP-POST, which carries a request of the HTTP-Redirect binding.
	if r.Body != nil {
		r.Body = http.MaxBytesReader(rw, r.Body, samlidp.MaxBodyLength)
	}

	if err := r.ParseForm(); err != nil || len(r.Form.Get("SAMLRequest")) > samlidp.MaxRequestLength || len(r.Form.Get("RelayState")) > samlidp.MaxRelayStateLength ||
		len(r.Form.Get("SAMLRedirectQuery")) > samlidp.MaxRequestLength+samlidp.MaxRelayStateLength+1024 {
		ctx.GetLogger().WithError(err).Error("Error occurred handling a SAML authentication request: the request or its RelayState is too long")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	// A service provider whose request signatures are ignored may still sign its requests, which the library would
	// verify.
	ctx.Providers.SAML.IgnoreRequestSignature(r)

	rw.Header().Set("Content-Security-Policy", samlidp.ContentSecurityPolicy)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")

	idp.ServeSSO(rw, r.WithContext(context.WithValue(r.Context(), ctxKeySAMLAutheliaCtx{}, ctx)))
}

// SAMLSSOResumeGET resumes a SAML authentication request once the user has logged in: the request kept for the flow
// is presented to the single sign-on endpoint again, as the form a login page would post. A flow can be used once.
func SAMLSSOResumeGET(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request) {
	// Resuming uses up a pending request rather than keeping one, so it doesn't count against the rate limit; a resumed
	// request which keeps a new one does.
	ctx.SetUserValue(middlewares.UserValueRateLimitExempt, true)

	idp, ok := samlIdentityProvider(ctx, rw)
	if !ok {
		return
	}

	flow, err := ctx.Providers.StorageProvider.ConsumeSAMLFlow(ctx, r.URL.Query().Get(queryArgFlowID))
	if err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred resuming a SAML authentication request")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	form := url.Values{}

	if err = json.Unmarshal([]byte(flow.Form), &form); err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred decoding a SAML authentication request")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	resumeCtx := context.WithValue(context.WithValue(r.Context(), ctxKeySAMLAutheliaCtx{}, ctx), ctxKeySAMLResumed{}, true)
	resumeCtx = context.WithValue(resumeCtx, ctxKeySAMLFlowCreatedAt{}, flow.CreatedAt)

	resume, err := http.NewRequestWithContext(resumeCtx, http.MethodPost, idp.SSOURL.String(), strings.NewReader(form.Encode()))
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	resume.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resume.RemoteAddr = r.RemoteAddr

	rw.Header().Set("Content-Security-Policy", samlidp.ContentSecurityPolicy)
	rw.Header().Set("Content-Type", "text/html; charset=utf-8")

	idp.ServeSSO(rw, resume)
}

func samlIdentityProvider(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter) (idp *saml.IdentityProvider, ok bool) {
	issuer, err := ctx.IssuerURL()
	if err != nil || ctx.Providers.SAML == nil || !samlIsConfiguredIssuer(ctx, issuer) {
		ctx.GetLogger().WithError(err).Error("Error occurred determining the issuer of a SAML request: SAML is only served at a configured authelia_url")
		http.Error(rw, http.StatusText(http.StatusNotFound), http.StatusNotFound)

		return nil, false
	}

	return ctx.Providers.SAML.IdentityProvider(issuer, samlSessions{}, samlObserver{}), true
}

// samlIsConfiguredIssuer returns true if the issuer is the authelia_url of a session cookie. The identity provider of
// an issuer is kept for the life of the process, so only these issuers get one.
func samlIsConfiguredIssuer(ctx *middlewares.AutheliaCtx, issuer *url.URL) bool {
	for _, cookie := range ctx.Configuration.Session.Cookies {
		if cookie.AutheliaURL != nil && strings.TrimSuffix(cookie.AutheliaURL.String(), "/") == strings.TrimSuffix(issuer.String(), "/") {
			return true
		}
	}

	return false
}

// samlSessions is the session provider of the identity provider: the session of the Authelia portal.
type samlSessions struct{}

// GetSession implements saml.SessionProvider. It returns the session of the logged in user when its authentication
// level satisfies the service provider, and otherwise keeps the request in the session and sends the user to the
// portal, which resumes it once the user has logged in.
func (samlSessions) GetSession(rw http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	ctx, ok := r.Context().Value(ctxKeySAMLAutheliaCtx{}).(*middlewares.AutheliaCtx)
	if !ok || req.ServiceProviderMetadata == nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return nil
	}

	sp := ctx.Providers.SAML.ServiceProvider(req.ServiceProviderMetadata.EntityID)
	if sp == nil {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)

		return nil
	}

	userSession, err := ctx.GetSession()
	if err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred retrieving the session for a SAML authentication request")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return nil
	}

	level := userSession.AuthenticationLevel(ctx.Configuration.WebAuthn.EnablePasskey2FA)

	if userSession.IsAnonymous() || !authorization.IsAuthLevelSufficient(level, samlRequiredLevel(sp)) {
		if resumed, _ := r.Context().Value(ctxKeySAMLResumed{}).(bool); resumed {
			ctx.GetLogger().WithField(logging.FieldUsername, userSession.Username).Error("Failed to resume a SAML authentication request as the session doesn't satisfy the authorization policy of the service provider")
			http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)

			return nil
		}

		samlLoginRedirect(ctx, rw, r, req, sp)

		return nil
	}

	// The user is checked again, as forward-auth does: a disabled or deleted user is not asserted.
	details, err := ctx.Providers.UserProvider.GetDetailsExtended(userSession.Username)
	if err != nil {
		ctx.GetLogger().WithError(err).WithField(logging.FieldUsername, userSession.Username).Error("Error occurred retrieving the details of the user for a SAML authentication request")
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)

		return nil
	}

	return newSAMLSession(&userSession, details, sp, level)
}

// GetForcedSession implements saml.ForceAuthnSessionProvider: a request with ForceAuthn ends the portal session and
// sends the user to log in again, and once it is resumed it is answered for a login made after the request, as
// Keycloak asks for the credentials again.
func (p samlSessions) GetForcedSession(rw http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	ctx, ok := r.Context().Value(ctxKeySAMLAutheliaCtx{}).(*middlewares.AutheliaCtx)
	if !ok || req.ServiceProviderMetadata == nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return nil
	}

	// A request of a service provider whose signatures are ignored can't be told from one anybody made, so its
	// ForceAuthn is ignored too: otherwise any site could end the user's portal session with it.
	if ctx.Providers.SAML.ServiceProvider(req.ServiceProviderMetadata.EntityID).IgnoresRequestSignature() {
		return p.GetSession(rw, r, req)
	}

	// A resumed request is answered for a login made after it. Otherwise, as when a cross-site HTTP-POST request didn't
	// carry the session cookie which the portal then resumed it with, the session is ended below and the user logs in:
	// with the session gone this can't loop.
	if created, resumed := r.Context().Value(ctxKeySAMLFlowCreatedAt{}).(time.Time); resumed {
		if userSession, err := ctx.GetSession(); err == nil && !userSession.IsAnonymous() && !userSession.GetFirstFactorAuthn().Before(created.Truncate(time.Second)) {
			return p.GetSession(rw, r, req)
		}
	}

	sp := ctx.Providers.SAML.ServiceProvider(req.ServiceProviderMetadata.EntityID)
	if sp == nil {
		http.Error(rw, http.StatusText(http.StatusForbidden), http.StatusForbidden)

		return nil
	}

	if err := ctx.DestroySession(); err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred ending the session for a SAML authentication request with ForceAuthn")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return nil
	}

	samlLoginRedirect(ctx, rw, r, req, sp)

	return nil
}

func samlRequiredLevel(sp *samlidp.ServiceProvider) authorization.Level {
	if sp.Config.AuthorizationPolicy == "one_factor" {
		return authorization.OneFactor
	}

	return authorization.TwoFactor
}

// samlLoginRedirect keeps the request for a SAML flow and sends the user to the portal with it.
func samlLoginRedirect(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, r *http.Request, req *saml.IdpAuthnRequest, sp *samlidp.ServiceProvider) {
	issuer, err := ctx.IssuerURL()
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	form, err := json.Marshal(req.ResumeFormValues())
	if err != nil {
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	// Keeping a pending request counts against the rate limit of the single sign-on endpoints.
	ctx.SetUserValue(middlewares.UserValueRateLimitExempt, false)

	// Whichever binding or field the request came in, what is kept is bounded.
	if len(req.RelayState) > samlidp.MaxRelayStateLength || len(form) > samlidp.MaxStoredRequestLength {
		ctx.GetLogger().Error("Error occurred keeping a SAML authentication request: the request or its RelayState is too long")
		http.Error(rw, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)

		return
	}

	now := ctx.GetClock().Now()

	flow := model.SAMLFlow{
		FlowID:          uuid.NewString(),
		CreatedAt:       now,
		ExpiresAt:       now.Add(samlFlowLifespan),
		ServiceProvider: sp.Config.EntityID,
		Form:            string(form),
	}

	if err = ctx.Providers.StorageProvider.SaveSAMLFlow(ctx, flow); err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred saving a SAML authentication request")
		http.Error(rw, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	location := *issuer

	if !strings.HasSuffix(location.Path, "/") {
		location.Path += "/"
	}

	query := url.Values{}
	query.Set(queryArgFlow, flowNameSAML)
	query.Set(queryArgFlowID, flow.FlowID)
	location.RawQuery = query.Encode()

	// The location is the configured issuer with the flow parameters, never a value of the request.
	http.Redirect(rw, r, location.String(), http.StatusSeeOther) //nolint:gosec // See above.
}

func newSAMLSession(userSession *session.UserSession, details *authentication.UserDetailsExtended, sp *samlidp.ServiceProvider, level authentication.Level) *saml.Session {
	// The session index is derived from the public identifier, never from the session identifier itself.
	index := sha256.Sum256([]byte("authelia:saml:session-index:" + userSession.PublicID))

	s := &saml.Session{
		ID:              userSession.PublicID,
		CreateTime:      time.Unix(userSession.FirstFactorAuthnTimestamp, 0),
		Index:           hex.EncodeToString(index[:]),
		UserName:        details.Username,
		Groups:          details.Groups,
		UserCommonName:  details.DisplayName,
		UserDisplayName: details.DisplayName,
		UserGivenName:   details.GivenName,
		UserSurname:     details.FamilyName,
		// The library states the client address as the Address of the SubjectConfirmationData and the SubjectLocality,
		// falling back to the address of the request when it's empty, and leaves out a value which isn't an IP address.
		// Leaving it out, as Keycloak does, doesn't disclose the user's IP address to service providers, nor fails those
		// which check it behind a proxy.
		ClientAddress: samlClientAddressNone,
	}

	if len(details.Emails) != 0 {
		s.UserEmail = details.Emails[0]
	}

	switch sp.Config.NameIDFormat {
	case "unspecified":
		s.NameID, s.NameIDFormat = details.Username, string(saml.UnspecifiedNameIDFormat)
	default:
		s.NameID, s.NameIDFormat = s.UserEmail, string(saml.EmailAddressNameIDFormat)
	}

	if level >= authentication.TwoFactor {
		s.AuthnContextClassRef = samlRefedsMFA
	}

	s.CustomAttributes = samlAttributes(sp, details)

	return s
}

// samlAttributes returns the attributes the service provider is configured to receive.
func samlAttributes(sp *samlidp.ServiceProvider, details *authentication.UserDetailsExtended) (attributes []saml.Attribute) {
	for _, name := range sp.Config.Attributes {
		var values []string

		switch name {
		case "username":
			values = []string{details.Username}
		case "email":
			values = details.Emails
		case "name":
			values = []string{details.DisplayName}
		case "given_name":
			values = []string{details.GivenName}
		case "family_name":
			values = []string{details.FamilyName}
		case "groups":
			values = details.Groups
		}

		attribute := saml.Attribute{Name: name, NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"}

		for _, value := range values {
			if value != "" {
				attribute.Values = append(attribute.Values, saml.AttributeValue{Type: "xs:string", Value: value})
			}
		}

		if len(attribute.Values) != 0 {
			attributes = append(attributes, attribute)
		}
	}

	return attributes
}

// samlObserver logs the events of the identity provider.
type samlObserver struct{}

// Observe implements saml.Observer.
func (samlObserver) Observe(_ context.Context, event saml.Event) {
	entry := logging.Logger().WithFields(event.Fields())

	if event.Err != nil {
		entry.Error(fmt.Sprintf("SAML %s", event.String()))

		return
	}

	entry.Debug(fmt.Sprintf("SAML %s", event.String()))
}

// resolveFlowResponseSAML continues a SAML flow after a login step: it resumes the request once the session satisfies
// the authorization policy of the service provider, and asks for the second factor otherwise. It only reads the flow;
// the single sign-on endpoint checks the session again when the request is resumed.
func resolveFlowResponseSAML(ctx *middlewares.AutheliaCtx, userSession *session.UserSession, id string) flowResponse {
	fields := map[string]any{logging.FieldFlowID: id, logging.FieldFlow: flowNameSAML, logging.FieldUsername: userSession.Username}

	if userSession.IsAnonymous() || ctx.Providers.SAML == nil {
		ctx.GetLogger().WithFields(fields).Error("Failed to continue the SAML flow as the user is anonymous or SAML is not configured")

		return newFlowResponseFailure(messageAuthenticationFailed)
	}

	flow, err := ctx.Providers.StorageProvider.LoadSAMLFlow(ctx, id)
	if err != nil {
		ctx.GetLogger().WithError(err).WithFields(fields).Error("Error occurred loading the SAML flow")

		return newFlowResponseFailure(messageAuthenticationFailed)
	}

	sp := ctx.Providers.SAML.ServiceProvider(flow.ServiceProvider)
	if sp == nil {
		ctx.GetLogger().WithFields(fields).Error("Failed to continue the SAML flow as its service provider is no longer registered")

		return newFlowResponseFailure(messageAuthenticationFailed)
	}

	if !authorization.IsAuthLevelSufficient(userSession.AuthenticationLevel(ctx.Configuration.WebAuthn.EnablePasskey2FA), samlRequiredLevel(sp)) {
		return newFlowResponseSecondFactor()
	}

	issuer, err := ctx.IssuerURL()
	if err != nil {
		ctx.GetLogger().WithError(err).WithFields(fields).Error("Error occurred determining the issuer")

		return newFlowResponseFailure(messageAuthenticationFailed)
	}

	target := issuer.JoinPath(samlEndpointPathResume)

	query := url.Values{}
	query.Set(queryArgFlowID, id)
	target.RawQuery = query.Encode()

	return newFlowResponseRedirect(target.String())
}
