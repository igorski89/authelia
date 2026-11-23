// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"github.com/authelia/authelia/v4/internal/middlewares"
)

// AdminWhoAmIResponse is the body of a successful response from the AdminWhoAmIGET handler.
type AdminWhoAmIResponse struct {
	ClientID string `json:"client_id"`
}

// AdminWhoAmIGET returns the identity of the client calling the administration API, so that a client can check its
// credentials and scopes before it changes anything.
func AdminWhoAmIGET(ctx *middlewares.AutheliaCtx) {
	if err := ctx.ReplyJSON(AdminWhoAmIResponse{ClientID: ctx.BearerClientID()}, 0); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred encoding JSON response.")
	}
}
