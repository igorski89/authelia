// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package middlewares

import (
	"testing"

	oauthelia2 "authelia.com/provider/oauth2"
	"github.com/stretchr/testify/assert"

	"github.com/authelia/authelia/v4/internal/oidc"
)

func TestBearerAudienceGrantedIsExact(t *testing.T) {
	const audience = "https://auth.example.com/api/admin"

	requester := func(audiences ...string) oauthelia2.AccessRequester {
		return &oauthelia2.AccessRequest{Request: oauthelia2.Request{GrantedAudience: audiences}}
	}

	exact := &oidc.RegisteredClient{Audience: []string{audience}}
	parent := &oidc.RegisteredClient{Audience: []string{"https://auth.example.com/api"}}

	assert.True(t, bearerAudienceGranted(requester(audience), exact, audience))
	assert.False(t, bearerAudienceGranted(requester("https://auth.example.com/api"), parent, audience), "a parent audience, which a prefix strategy would match")
	assert.False(t, bearerAudienceGranted(requester(audience), parent, audience), "the client isn't registered for the audience")
	assert.False(t, bearerAudienceGranted(requester("https://auth.example.com/api/admin/other"), exact, audience))
}
