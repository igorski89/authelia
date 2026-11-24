// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"bytes"
	"fmt"
	"net/url"
	"slices"

	"github.com/valyala/fasthttp"

	oauthelia2 "authelia.com/provider/oauth2"
	"authelia.com/provider/oauth2/handler/oauth2"

	"github.com/authelia/authelia/v4/internal/oidc"
)

// RequireBearerClientCredentials permits a request only when it carries an OAuth 2.0 Access Token which this server
// issued with the client credentials grant, granted the given scope and the audience (or resource) formed by joining
// the issuer with the given path, to a client which is still registered with that scope and audience. The client
// identifier is stored on the context for the next handler (see [AutheliaCtx.BearerClientID]).
func RequireBearerClientCredentials(path, scope string) AutheliaMiddleware {
	return func(next RequestHandler) RequestHandler {
		return func(ctx *AutheliaCtx) {
			clientID, rfc := bearerClientCredentials(ctx, path, scope)
			if rfc != nil {
				ctx.Logger.WithFields(map[string]any{"client_id": clientID, "scope": scope}).
					Errorf("Bearer authorization was refused: %s", oauthelia2.ErrorToDebugRFC6749Error(rfc))

				replyBearerError(ctx, scope, rfc)

				return
			}

			ctx.SetUserValue(UserValueKeyBearerClientID, clientID)

			next(ctx)
		}
	}
}

// BearerClientID returns the client identifier stored by [RequireBearerClientCredentials].
func (ctx *AutheliaCtx) BearerClientID() string {
	if clientID, ok := ctx.UserValue(UserValueKeyBearerClientID).(string); ok {
		return clientID
	}

	return ""
}

func bearerClientCredentials(ctx *AutheliaCtx, path, scope string) (clientID string, rfc *oauthelia2.RFC6749Error) {
	if ctx.Providers.OpenIDConnect == nil {
		return "", oauthelia2.ErrServerError.WithDebug("The OpenID Connect 1.0 provider is not configured.")
	}

	token, ok := bearerTokenFromHeader(ctx.Request.Header.Peek(fasthttp.HeaderAuthorization))
	if !ok {
		return "", errBearerTokenMissing
	}

	var (
		issuer    *url.URL
		tokenType oauthelia2.TokenType
		requester oauthelia2.AccessRequester
		client    oidc.Client
		err       error
	)

	if issuer, err = ctx.IssuerURL(); err != nil {
		return "", oidc.ErrEffectiveIssuer.WithWrap(err)
	}

	if tokenType, requester, err = ctx.Providers.OpenIDConnect.IntrospectToken(oauth2.SetSkipStatelessIntrospection(ctx), token, oauthelia2.AccessToken, oidc.NewSessionWithRequestedAt(ctx.GetClock().Now())); err != nil {
		return "", errBearerTokenInvalid.WithWrap(err).WithDebug(oauthelia2.ErrorToDebugRFC6749Error(err).Error())
	}

	clientID = requester.GetClient().GetID()

	if tokenType != oauthelia2.AccessToken {
		return clientID, errBearerTokenInvalid.WithHint("Only Access Tokens are permitted.")
	}

	session, ok := requester.GetSession().(*oidc.Session)
	if !ok {
		return clientID, oauthelia2.ErrServerError.WithDebugf("Failed to handle session with type '%T'.", requester.GetSession())
	}

	if !session.ValidIssuer(issuer) {
		return clientID, errBearerTokenInvalid.WithHint("The Access Token was issued by a different issuer.")
	}

	if !session.ClientCredentials {
		return clientID, oauthelia2.ErrInsufficientScope.WithHint("Only Access Tokens issued with the client credentials grant are permitted.")
	}

	if client, err = ctx.Providers.OpenIDConnect.GetRegisteredClient(ctx, clientID); err != nil || client == nil {
		return clientID, errBearerTokenInvalid.WithHint("The client the Access Token was issued to is no longer registered.")
	}

	if !bearerScopeGranted(requester, client, scope) {
		return clientID, oauthelia2.ErrInsufficientScope.WithHintf("The Access Token was not granted the '%s' scope.", scope)
	}

	audience := issuer.JoinPath(path).String()

	if !bearerAudienceGranted(requester, client, audience) {
		return clientID, errBearerTokenInvalid.WithHintf("The Access Token was not issued for the audience '%s'.", audience)
	}

	if bearerScopeGranted(requester, client, oidc.ScopeAutheliaAdminRead) {
		ctx.SetUserValue(UserValueKeyBearerCanRead, true)
	}

	return clientID, nil
}

// bearerScopeGranted returns true if the scope was granted to the token and the client still holds it.
func bearerScopeGranted(requester oauthelia2.AccessRequester, client oidc.Client, scope string) bool {
	return client.GetScopes().Has(scope) && requester.GetGrantedScopes().Has(scope)
}

// bearerAudienceGranted returns true if the audience was granted to the token and registered for the client exactly,
// not matched by a prefix or wildcard audience or resource strategy of the client: only a token issued for this API
// may use it.
func bearerAudienceGranted(requester oauthelia2.AccessRequester, client oidc.Client, audience string) bool {
	granted := slices.Contains(requester.GetGrantedAudience(), audience) || slices.Contains(requester.GetGrantedResource(), audience)
	registered := slices.Contains(client.GetAudience(), audience) || slices.Contains(client.GetResource(), audience)

	return granted && registered
}

// BearerCanRead returns true if the Access Token stored by [RequireBearerClientCredentials] may also read, so a change
// may answer with what it changed.
func (ctx *AutheliaCtx) BearerCanRead() bool {
	canRead, _ := ctx.UserValue(UserValueKeyBearerCanRead).(bool)

	return canRead
}

func bearerTokenFromHeader(value []byte) (token string, ok bool) {
	scheme, raw, found := bytes.Cut(bytes.TrimSpace(value), []byte(" "))
	if !found || !bytes.EqualFold(scheme, []byte("Bearer")) {
		return "", false
	}

	if raw = bytes.TrimSpace(raw); len(raw) == 0 {
		return "", false
	}

	return string(raw), true
}

// errBearerTokenInvalid is the RFC 6750 Section 3.1 'invalid_token' error.
var errBearerTokenInvalid = &oauthelia2.RFC6749Error{
	ErrorField:       "invalid_token",
	DescriptionField: "The Access Token provided is expired, revoked, malformed, or invalid for other reasons.",
	CodeField:        fasthttp.StatusUnauthorized,
}

// errBearerTokenMissing is a request without an Access Token, which RFC 6750 Section 3.1 answers without an error code.
var errBearerTokenMissing = &oauthelia2.RFC6749Error{
	DescriptionField: "The request must carry an Access Token using the Bearer scheme.",
	CodeField:        fasthttp.StatusUnauthorized,
}

func replyBearerError(ctx *AutheliaCtx, scope string, rfc *oauthelia2.RFC6749Error) {
	status := rfc.StatusCode()

	switch {
	case rfc == errBearerTokenMissing:
		ctx.Response.Header.Set(fasthttp.HeaderWWWAuthenticate, "Bearer")
	case status == fasthttp.StatusUnauthorized || status == fasthttp.StatusForbidden:
		ctx.Response.Header.Set(fasthttp.HeaderWWWAuthenticate, fmt.Sprintf("Bearer %s", oidc.RFC6750Header("", scope, rfc)))
	}

	body := map[string]string{"error_description": rfc.GetDescription()}

	if rfc.ErrorField != "" {
		body["error"] = rfc.ErrorField
	}

	if err := ctx.ReplyJSON(body, status); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred encoding JSON response during bearer authorization.")
	}
}
