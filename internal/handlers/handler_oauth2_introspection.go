// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"errors"
	"net/http"
	"net/url"

	"github.com/google/uuid"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// OAuth2IntrospectionPOST handles POST requests to the OAuth 2.0 Introspection endpoint.
//
// https://datatracker.ietf.org/doc/html/rfc7662
func OAuth2IntrospectionPOST(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
	var (
		issuer    *url.URL
		requestID uuid.UUID
		responder oauthelia2.IntrospectionResponder
		err       error
	)

	if requestID, err = uuid.NewRandom(); err != nil {
		ctx.Providers.OpenIDConnect.WriteIntrospectionError(ctx, rw, oauthelia2.ErrServerError)

		return
	}

	ctx.GetLogger().Debugf("Introspection Request with id '%s' is being processed", requestID)

	if issuer, err = ctx.IssuerURL(); err != nil {
		rfc := oidc.ErrEffectiveIssuer.WithWrap(err)

		ctx.GetLogger().WithError(err).Errorf("Introspection Request with id '%s' could not be processed: %s", requestID, oauthelia2.ErrorToDebugRFC6749Error(rfc))

		ctx.Providers.OpenIDConnect.WriteIntrospectionError(ctx, rw, rfc)

		return
	}

	if responder, err = ctx.Providers.OpenIDConnect.NewIntrospectionRequest(ctx, req, oidc.NewSessionWithRequestedAt(ctx.GetClock().Now())); err != nil {
		ctx.GetLogger().WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).Errorf("Introspection Request with id '%s' failed with error", requestID)

		ctx.Providers.OpenIDConnect.WriteIntrospectionError(ctx, rw, err)

		return
	}

	requester := responder.GetAccessRequester()

	if requester != nil {
		if s := requester.GetSession(); s != nil {
			if session, ok := s.(*oidc.Session); ok {
				if !session.ValidIssuer(issuer) {
					err = oauthelia2.ErrInvalidRequest.WithDebug("The original request and the introspection request occurred at endpoints where the origin or effective issuer did not match.")

					ctx.GetLogger().WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).Errorf("Introspection Request with id '%s' failed with error", requestID)

					ctx.Providers.OpenIDConnect.WriteIntrospectionError(ctx, rw, err)

					return
				}
			}
		}

		ctx.GetLogger().Tracef("Introspection Request with id '%s' yielded a %s (active: %t) requested at %s created with request id '%s' on client with id '%s'", requestID, responder.GetTokenUse(), responder.IsActive(), requester.GetRequestedAt().String(), requester.GetID(), requester.GetClient().GetID())
	} else {
		ctx.GetLogger().Tracef("Introspection Request with id '%s' yielded a %s (active: %t)", requestID, responder.GetTokenUse(), responder.IsActive())
	}

	handleOAuth2IntrospectionUserPermitted(ctx, requestID, responder)

	if responder.IsActive() {
		ctx.SetUserValue(middlewares.UserValueRateLimitExempt, true)
	}

	ctx.Providers.OpenIDConnect.WriteIntrospectionResponse(ctx, rw, responder)
}

// handleOAuth2IntrospectionUserPermitted reports an otherwise active token as inactive when the user it was issued to
// has since been deleted or disabled. Only the user provider reporting the user as not found does this; any other
// error is logged and the token stays active, so a transient failure doesn't revoke every token at once.
func handleOAuth2IntrospectionUserPermitted(ctx *middlewares.AutheliaCtx, requestID uuid.UUID, responder oauthelia2.IntrospectionResponder) {
	response, ok := responder.(*oauthelia2.IntrospectionResponse)
	if !ok || !response.IsActive() || response.GetAccessRequester() == nil {
		return
	}

	session, ok := response.GetAccessRequester().GetSession().(*oidc.Session)
	if !ok || session.ClientCredentials || len(session.Subject) == 0 {
		return
	}

	detailer, err := oidc.UserDetailerFromSubjectString(ctx, session.Subject)
	if err == nil {
		var revoked bool

		clientID := ""
		if client := response.GetAccessRequester().GetClient(); client != nil {
			clientID = client.GetID()
		}

		if revoked, err = middlewares.IsUserRevoked(ctx, ctx.Providers.StorageProvider, detailer.GetUsername(), clientID, session.GetRequestedAt()); err == nil && revoked {
			ctx.GetLogger().WithField("subject", session.Subject).Infof("Introspection Request with id '%s' yielded an inactive token as it was revoked since the user logged in", requestID)

			response.Active = false

			return
		}
	}

	switch {
	case err == nil:
		return
	case errors.Is(err, authentication.ErrUserNotFound):
		ctx.GetLogger().WithField("subject", session.Subject).Infof("Introspection Request with id '%s' yielded an inactive token as the user it was issued to is no longer permitted to log in", requestID)

		response.Active = false
	default:
		ctx.GetLogger().WithError(err).WithField("subject", session.Subject).Errorf("Introspection Request with id '%s' could not check the user the token was issued to", requestID)
	}
}
