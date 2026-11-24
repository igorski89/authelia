// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"net/http"
	"net/url"

	"github.com/authelia/authelia/v4/internal/middlewares"
)

// handleOAuth2ImplicitAudienceWithResource adds the configured audience of a client with the option
// 'implicit_audience_with_resource' to a request which names a resource (RFC 8707) but no audience. The library only
// adds the audience of a client to a request which names neither, while an MCP client always names its resource, so its
// token would not be for the client which exchanges it. The audience is added to the form before the library parses it,
// so the library validates it as if the client had requested it: against the client's audience at the authorization
// endpoint, and against the audience the user consented to at the token endpoint.
func handleOAuth2ImplicitAudienceWithResource(ctx *middlewares.AutheliaCtx, r *http.Request) {
	if r == nil || ctx.Providers.OpenIDConnect == nil {
		return
	}

	// An error is reported by the library when it parses the form itself.
	if err := r.ParseForm(); err != nil {
		return
	}

	if !r.Form.Has(formParameterResource) || r.Form.Has(formParameterAudience) {
		return
	}

	id := r.Form.Get(formParameterClientID)

	if id == "" {
		if username, _, ok := r.BasicAuth(); ok {
			id, _ = url.QueryUnescape(username)
		}
	}

	client, err := ctx.Providers.OpenIDConnect.GetRegisteredClient(ctx, id)
	if err != nil || client == nil || !client.GetImplicitAudienceWithResource() {
		return
	}

	for _, audience := range client.GetAudience() {
		r.Form.Add(formParameterAudience, audience)

		if r.PostForm != nil && r.PostForm.Has(formParameterResource) {
			r.PostForm.Add(formParameterAudience, audience)
		}
	}

	ctx.GetLogger().WithFields(map[string]any{"client_id": id, "audience": client.GetAudience()}).Debug("OAuth 2.0 request names a resource but no audience, so the client's audience was added")
}

const (
	formParameterResource = "resource"
	formParameterAudience = "audience"
	formParameterClientID = "client_id"
)
