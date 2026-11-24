// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"errors"
	"net/http"
	"net/url"

	oauthelia2 "authelia.com/provider/oauth2"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/oidc"
)

// OAuth2TokenPOST handles POST requests to the OpenID Connect 1.0 Token endpoint.
//
// https://openid.net/specs/openid-connect-core-1_0.html#TokenEndpoint
func OAuth2TokenPOST(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, req *http.Request) {
	var (
		issuer    *url.URL
		requester oauthelia2.AccessRequester
		responder oauthelia2.AccessResponder
		err       error
	)

	if issuer, err = ctx.IssuerURL(); err != nil {
		rfc := oidc.ErrEffectiveIssuer.WithWrap(err)

		ctx.GetLogger().WithError(err).Errorf("Access Request could not be processed: %s", oauthelia2.ErrorToDebugRFC6749Error(rfc))

		ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, rfc)

		return
	}

	session := oidc.NewSessionWithIssuerAndRequestedAt(ctx, issuer, ctx.GetClock().Now())

	if requester, err = ctx.Providers.OpenIDConnect.NewAccessRequest(ctx, req, session); err != nil {
		ctx.GetLogger().Errorf("Access Request failed with error: %s", oauthelia2.ErrorToDebugRFC6749Error(err))

		if req.PostForm.Get(oidc.FormParameterGrantType) == oidc.GrantTypeTokenExchange {
			logOAuth2TokenExchange(ctx, requester, nil, err)
		}

		ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

		return
	}

	if !session.ValidIssuer(issuer) {
		err = oauthelia2.ErrInvalidRequest.WithDebug("The original request and the access request occurred at endpoints where the effective issuer did not match.")

		ctx.GetLogger().WithError(err).Errorf("Access Request with id '%s' could not be processed: %s", requester.GetID(), oauthelia2.ErrorToDebugRFC6749Error(err))

		logOAuth2TokenExchange(ctx, requester, nil, err)

		ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

		return
	}

	ctx.GetLogger().Debugf("Access Request with id '%s' is being processed", requester.GetID())

	client, ok := requester.GetClient().(oidc.Client)
	if !ok {
		err = oauthelia2.ErrServerError.WithDebug("The requester contained an unknown client implementation")

		ctx.GetLogger().Errorf("Access Response for Request with id '%s' failed with error: %s", requester.GetID(), oauthelia2.ErrorToDebugRFC6749Error(err))

		logOAuth2TokenExchange(ctx, requester, nil, err)

		ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

		return
	}

	ctx.GetLogger().
		WithFields(map[string]any{
			"access_request_id":                       requester.GetID(),
			"client_id":                               client.GetID(),
			"subject":                                 session.Subject,
			"access_token_signed_response_kid":        client.GetAccessTokenSignedResponseKeyID(),
			"access_token_signed_response_alg":        client.GetAccessTokenSignedResponseAlg(),
			"access_token_encrypted_response_kid":     client.GetAccessTokenEncryptedResponseKeyID(),
			"access_token_encrypted_response_alg":     client.GetAccessTokenEncryptedResponseAlg(),
			"access_token_encrypted_response_enc":     client.GetAccessTokenEncryptedResponseEnc(),
			"enable_jwt_profile_oauth2_access_tokens": client.GetEnableJWTProfileOAuthAccessTokens(),
		}).
		Trace("Access Request is being handled by a provider")

	ctx.GetLogger().Debugf("Access Request with id '%s' on client with id '%s' is being processed", requester.GetID(), client.GetID())

	if handled := handleOAuth2TokenUserPermitted(ctx, rw, requester, client, requester.GetSession().(*oidc.Session)); handled {
		return
	}

	if handled := handleOAuth2TokenHydration(ctx, rw, requester, client, requester.GetSession().(*oidc.Session)); handled {
		return
	}

	ctx.GetLogger().Tracef("Access Request with id '%s' on client with id '%s' response is being generated for session with type '%T'", requester.GetID(), client.GetID(), requester.GetSession())

	if responder, err = ctx.Providers.OpenIDConnect.NewAccessResponse(ctx, requester); err != nil {
		ctx.GetLogger().Errorf("Access Response for Request with id '%s' failed to be created with error: %s", requester.GetID(), oauthelia2.ErrorToDebugRFC6749Error(err))

		logOAuth2TokenExchange(ctx, requester, nil, err)

		ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

		return
	}

	logOAuth2TokenExchange(ctx, requester, responder, nil)

	ctx.GetLogger().Debugf("Access Request with id '%s' on client with id '%s' has successfully been processed", requester.GetID(), client.GetID())

	ctx.GetLogger().Tracef("Access Request with id '%s' on client with id '%s' produced the following claims: %+v", requester.GetID(), client.GetID(), oidc.AccessResponderToClearMap(responder))

	ctx.Providers.OpenIDConnect.WriteAccessResponse(ctx, rw, requester, responder)
}

// handleOAuth2TokenUserPermitted refuses to issue tokens on behalf of a user who has since been deleted or disabled, for
// example when a refresh token is used after the user was disabled. Only the user provider reporting the user as not
// found refuses the grant; any other error is reported as a server error so a transient failure doesn't look final.
//
// For an RFC 8693 Token Exchange the session is a fresh one which only carries the subject of the 'subject_token', so
// the grant checked is the one the 'subject_token' was issued for: it's refused when the user was logged out of the
// client the 'subject_token' was issued to, or of the client performing the exchange, since that grant was authorized.
// A 'subject_token' issued via the client credentials grant has no user and is left to the token exchange policy.
func handleOAuth2TokenUserPermitted(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, requester oauthelia2.AccessRequester, client oidc.Client, session *oidc.Session) (handled bool) {
	if session.ClientCredentials || len(session.Subject) == 0 || requester.GetGrantTypes().ExactOne(oidc.GrantTypeClientCredentials) {
		return false
	}

	exchange := requester.GetGrantTypes().ExactOne(oidc.GrantTypeTokenExchange)

	if exchange && oidc.TokenExchangeSubjectClientCredentials(session) {
		return false
	}

	detailer, err := oidc.UserDetailerFromSubjectString(ctx, session.Subject)

	var revoked bool

	if err == nil {
		// A grant authorized before the user was logged out of the client is over, also when a request which was
		// already running issued it after the revocation. The time of the authorization request is compared, not the
		// time of the login: after a logout of one client the portal session stays and may authorize it again.
		revoked, err = handleOAuth2TokenUserRevoked(ctx, client, session, detailer.GetUsername(), exchange)
	}

	switch {
	case err == nil && !revoked:
		return false
	case err == nil:
		err = oauthelia2.ErrInvalidGrant.WithHint("The grant was revoked since the user logged in.")
	case errors.Is(err, authentication.ErrUserNotFound):
		err = oauthelia2.ErrInvalidGrant.WithHint("The user the grant was issued to is no longer permitted to log in.")
	default:
		err = oauthelia2.ErrServerError.WithWrap(err).WithDebugf("Failed to check the user the grant was issued to: %v.", err)
	}

	ctx.GetLogger().
		WithFields(map[string]any{"oauth2_access_request_id": requester.GetID(), "client_id": client.GetID(), "subject": session.Subject}).
		WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).
		Error("Access Request was refused as the user it was issued to could not be confirmed")

	logOAuth2TokenExchange(ctx, requester, nil, err)

	ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

	return true
}

func handleOAuth2TokenUserRevoked(ctx *middlewares.AutheliaCtx, client oidc.Client, session *oidc.Session, username string, exchange bool) (revoked bool, err error) {
	if !exchange {
		return middlewares.IsUserRevoked(ctx, ctx.Providers.StorageProvider, username, client.GetID(), session.GetRequestedAt(), middlewares.RevocationResolutionGrant)
	}

	original := session.GetSubjectRequester()
	if original == nil || original.GetClient() == nil || original.GetSession() == nil {
		return false, oauthelia2.ErrServerError.WithDebug("The token exchange session has no request the 'subject_token' was issued for.")
	}

	requestedAt := original.GetRequestedAt()

	if subject, ok := original.GetSession().(*oidc.Session); ok && subject.DefaultSession != nil && !subject.GetRequestedAt().IsZero() {
		requestedAt = subject.GetRequestedAt()
	}

	for _, clientID := range []string{original.GetClient().GetID(), client.GetID()} {
		if revoked, err = middlewares.IsUserRevoked(ctx, ctx.Providers.StorageProvider, username, clientID, requestedAt, middlewares.RevocationResolutionGrant); err != nil || revoked {
			return revoked, err
		}
	}

	return false, nil
}

func handleOAuth2TokenHydration(ctx *middlewares.AutheliaCtx, rw http.ResponseWriter, requester oauthelia2.AccessRequester, client oidc.Client, session *oidc.Session) (handled bool) {
	var err error

	if requester.GetGrantTypes().ExactOne(oidc.GrantTypeClientCredentials) {
		if err = oidc.HydrateClientCredentialsFlowSessionWithAccessRequest(ctx, client, session); err != nil {
			ctx.GetLogger().
				WithFields(map[string]any{"oauth2_access_request_id": requester.GetID()}).
				WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).
				Error("Access Request encountered an error while trying to hydrate the Client Credentials Flow claims")

			ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

			return true
		}

		if err = oidc.PopulateClientCredentialsFlowRequester(ctx, ctx.Providers.OpenIDConnect, client, requester); err != nil {
			ctx.GetLogger().
				WithFields(map[string]any{"oauth2_access_request_id": requester.GetID()}).
				WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).
				Error("Access Request encountered an error while trying to populate the Client Credentials Flow requester")

			ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

			return true
		}

		return false
	}

	exchange := requester.GetGrantTypes().ExactOne(oidc.GrantTypeTokenExchange)

	if exchange {
		// The RFC 8693 token type handlers load the subject token into a fresh session, so the identity of the client
		// performing the exchange and of the subject have to be established before the token is issued.
		oidc.HydrateTokenExchangeSessionWithRequestingClient(client, session)

		if _, err = handleOAuth2TokenExchangePolicy(ctx, requester, client, session); err != nil {
			logOAuth2TokenExchange(ctx, requester, nil, err)

			ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

			return true
		}
	}

	if client.GetEnableJWTProfileOAuthAccessTokens() {
		ctx.GetLogger().WithFields(map[string]any{"subject": session.Subject, "scope": requester.GetRequestedScopes()}).Debug("Hydrate JWT Profile Access Token claims")

		if len(session.Subject) == 0 {
			ctx.GetLogger().
				WithFields(map[string]any{"oauth2_access_request_id": requester.GetID()}).
				Trace("Access Request JWT Profile Claims Processing Skipped as no subject was provided")

			return false
		}

		var detailer oidc.UserDetailer

		if detailer, err = oidc.UserDetailerFromSubjectString(ctx, session.Subject); err != nil {
			ctx.GetLogger().
				WithFields(map[string]any{"oauth2_access_request_id": requester.GetID()}).
				WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).
				Error("Access Request encountered an error while trying to obtain the detailer to hydrate the JWT Profile Access Token claims")

			if exchange {
				logOAuth2TokenExchange(ctx, requester, nil, err)
			}

			ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

			return true
		}

		extra := map[string]any{}

		if err = client.GetClaimsStrategy().HydrateAccessTokenClaims(ctx, ctx.Providers.OpenIDConnect.GetScopeStrategy(ctx), client, requester.GetRequestedScopes(), nil, nil, detailer, requester.GetRequestedAt(), ctx.GetClock().Now(), nil, extra); err != nil {
			ctx.GetLogger().
				WithFields(map[string]any{"oauth2_access_request_id": requester.GetID()}).
				WithError(oauthelia2.ErrorToDebugRFC6749Error(err)).
				Error("Access Request encountered an error while trying to hydrate the JWT Profile Access Token claims")

			if exchange {
				logOAuth2TokenExchange(ctx, requester, nil, err)
			}

			ctx.Providers.OpenIDConnect.WriteAccessError(ctx, rw, requester, err)

			return true
		}

		ctx.GetLogger().WithFields(map[string]any{"extra": extra}).Debug("Access Request JWT Profile Claims Result")

		if len(extra) != 0 {
			if session.AccessToken == nil {
				session.AccessToken = &oidc.AccessTokenSession{
					Headers: map[string]any{},
					Claims:  extra,
				}
			} else {
				session.AccessToken.Claims = extra
			}
		}
	}

	return false
}
