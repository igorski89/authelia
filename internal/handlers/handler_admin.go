// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"

	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/management"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/storage"
)

const contentTypeAdminJSON = "application/json"

// AdminWhoAmIResponse is the body of a successful response from the AdminWhoAmIGET handler.
type AdminWhoAmIResponse struct {
	ClientID string `json:"client_id"`
}

// AdminErrorResponse is the body of an error response from the administration API.
type AdminErrorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

// AdminUsersResponse is the body of a successful response from the AdminUsersGET handler.
type AdminUsersResponse struct {
	Users []management.User `json:"users"`
	Limit int               `json:"limit"`
	Page  int               `json:"page"`
}

// AdminGroupsResponse is the body of a successful response from the AdminGroupsGET handler.
type AdminGroupsResponse struct {
	Groups []management.Group `json:"groups"`
}

// AdminGroupMembersResponse is the body of a successful response from the AdminGroupMembersGET handler.
type AdminGroupMembersResponse struct {
	Members []management.User `json:"members"`
}

// AdminUserLogoutRequest is the optional body of a request to the AdminUserLogoutPOST handler.
type AdminUserLogoutRequest struct {
	ClientID string `json:"client_id,omitempty"`
}

// AdminGroupRequest is the body of a request to the AdminGroupsPOST handler.
type AdminGroupRequest struct {
	Name string `json:"name"`
}

// AdminWhoAmIGET returns the identity of the client calling the administration API, so that a client can check its
// credentials and scopes before it changes anything.
func AdminWhoAmIGET(ctx *middlewares.AutheliaCtx) {
	replyAdmin(ctx, fasthttp.StatusOK, AdminWhoAmIResponse{ClientID: ctx.BearerClientID()})
}

// AdminUsersGET lists a page of users, with the optional query parameters 'limit' and 'page'.
func AdminUsersGET(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var (
			limit, page int
			err         error
		)

		if limit, err = adminQueryInt(ctx, "limit", management.DefaultPageSize); err != nil {
			replyAdminError(ctx, err)
			return
		}

		if page, err = adminQueryInt(ctx, "page", 0); err != nil {
			replyAdminError(ctx, err)
			return
		}

		var users []management.User

		if users, err = service.ListUsers(ctx, limit, page); err != nil {
			replyAdminError(ctx, err)
			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, AdminUsersResponse{Users: users, Limit: limit, Page: page})
	}
}

// AdminUserGET returns a user.
func AdminUserGET(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		user, err := service.GetUser(ctx, adminPathValue(ctx, "username"))
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, user)
	}
}

// AdminUsersPOST creates a user.
func AdminUsersPOST(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var in management.NewUser

		if err := decodeAdminBody(ctx, &in); err != nil {
			replyAdminError(ctx, err)
			return
		}

		user, err := service.CreateUser(adminActor(ctx), in)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Created user", "username", user.Username)

		replyAdmin(ctx, fasthttp.StatusCreated, user)
	}
}

// AdminUserPATCH changes the profile of a user, or disables or enables it.
func AdminUserPATCH(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var changes management.UserChanges

		if err := decodeAdminBody(ctx, &changes); err != nil {
			replyAdminError(ctx, err)
			return
		}

		// An empty change would only read the user, without the read scope and without an audit entry.
		if changes == (management.UserChanges{}) {
			replyAdminError(ctx, fmt.Errorf("%w: the request changes nothing", management.ErrInvalid))
			return
		}

		user, err := service.UpdateUser(adminActor(ctx), adminPathValue(ctx, "username"), changes)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Updated user", "username", user.Username)

		// The changed user is only returned to a token which may read it.
		if !ctx.BearerCanRead() {
			ctx.SetStatusCode(fasthttp.StatusNoContent)

			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, user)
	}
}

// AdminUserDELETE deletes a user.
func AdminUserDELETE(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		username := adminPathValue(ctx, "username")

		if err := service.DeleteUser(adminActor(ctx), username); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Deleted user", "username", username)

		ctx.SetStatusCode(fasthttp.StatusNoContent)
	}
}

// AdminUserPasswordPUT sets the password of a user, from a plain password or a password digest.
func AdminUserPasswordPUT(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var password management.Password

		if err := decodeAdminBody(ctx, &password); err != nil {
			replyAdminError(ctx, err)
			return
		}

		if password == (management.Password{}) {
			replyAdminError(ctx, fmt.Errorf("%w: either the password or the password digest is required; use DELETE to remove the password", management.ErrInvalid))
			return
		}

		username := adminPathValue(ctx, "username")

		if err := service.SetPassword(adminActor(ctx), username, password); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Set the password of user", "username", username)

		ctx.SetStatusCode(fasthttp.StatusNoContent)
	}
}

// AdminUserPasswordDELETE removes the password of a user.
func AdminUserPasswordDELETE(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		username := adminPathValue(ctx, "username")

		if err := service.SetPassword(adminActor(ctx), username, management.Password{}); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Removed the password of user", "username", username)

		ctx.SetStatusCode(fasthttp.StatusNoContent)
	}
}

// AdminUserLogoutPOST ends everything a user is logged in with: portal sessions, OAuth 2.0 and OpenID Connect 1.0
// tokens, and pre-configured consent. With a client_id in the body only the tokens of that client are revoked.
func AdminUserLogoutPOST(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var in AdminUserLogoutRequest

		if len(ctx.PostBody()) != 0 {
			if err := decodeAdminBody(ctx, &in); err != nil {
				replyAdminError(ctx, err)
				return
			}
		}

		username := adminPathValue(ctx, "username")

		revocation, err := service.RevokeUser(adminActor(ctx), username, in.ClientID)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Logged out user", "username", username, "client", in.ClientID)

		replyAdmin(ctx, fasthttp.StatusOK, revocation)
	}
}

// AdminUserGroupPUT adds a user to a group.
func AdminUserGroupPUT(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		username, group := adminPathValue(ctx, "username"), adminPathValue(ctx, "group")

		if err := service.AddUserToGroup(adminActor(ctx), username, group); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Added user to group", "username", username, "group", group)

		ctx.SetStatusCode(fasthttp.StatusNoContent)
	}
}

// AdminUserGroupDELETE removes a user from a group.
func AdminUserGroupDELETE(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		username, group := adminPathValue(ctx, "username"), adminPathValue(ctx, "group")

		if err := service.RemoveUserFromGroup(adminActor(ctx), username, group); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Removed user from group", "username", username, "group", group)

		ctx.SetStatusCode(fasthttp.StatusNoContent)
	}
}

// AdminAuditResponse is the body of a successful response from the AdminAuditGET handler.
type AdminAuditResponse struct {
	Entries []management.AuditEntry `json:"entries"`
	Limit   int                     `json:"limit"`
	Page    int                     `json:"page"`
}

// AdminEventsResponse is the body of a successful response from the AdminEventsGET handler.
type AdminEventsResponse struct {
	Events []management.AuthenticationEvent `json:"events"`
	Limit  int                              `json:"limit"`
	Page   int                              `json:"page"`
}

// AdminAuditGET lists the changes made through the administration API and the CLI, newest first, with the optional
// query parameters 'username', 'limit', and 'page'.
func AdminAuditGET(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		username, limit, page, err := adminListQuery(ctx)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		entries, err := service.ListAudit(ctx, username, limit, page)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, AdminAuditResponse{Entries: entries, Limit: limit, Page: page})
	}
}

// AdminEventsGET lists the authentication attempts, newest first, with the optional query parameters 'username',
// 'limit', and 'page'.
func AdminEventsGET(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		username, limit, page, err := adminListQuery(ctx)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		events, err := service.ListAuthenticationEvents(ctx, username, limit, page)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, AdminEventsResponse{Events: events, Limit: limit, Page: page})
	}
}

func adminListQuery(ctx *middlewares.AutheliaCtx) (username string, limit, page int, err error) {
	if limit, err = adminQueryInt(ctx, "limit", management.DefaultPageSize); err != nil {
		return "", 0, 0, err
	}

	if page, err = adminQueryInt(ctx, "page", 0); err != nil {
		return "", 0, 0, err
	}

	return string(ctx.QueryArgs().Peek("username")), limit, page, nil
}

// AdminGroupsGET lists the groups.
func AdminGroupsGET(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		groups, err := service.ListGroups(ctx)
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, AdminGroupsResponse{Groups: groups})
	}
}

// AdminGroupsPOST creates a group.
func AdminGroupsPOST(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var in AdminGroupRequest

		if err := decodeAdminBody(ctx, &in); err != nil {
			replyAdminError(ctx, err)
			return
		}

		if err := service.CreateGroup(adminActor(ctx), in.Name); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Created group", "group", in.Name)

		replyAdmin(ctx, fasthttp.StatusCreated, AdminGroupRequest{Name: in.Name})
	}
}

// AdminGroupDELETE deletes a group and its memberships.
func AdminGroupDELETE(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		group := adminPathValue(ctx, "group")

		if err := service.DeleteGroup(adminActor(ctx), group); err != nil {
			replyAdminError(ctx, err)
			return
		}

		logAdminChange(ctx, "Deleted group", "group", group)

		ctx.SetStatusCode(fasthttp.StatusNoContent)
	}
}

// AdminGroupMembersGET lists the members of a group.
func AdminGroupMembersGET(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		members, err := service.GroupMembers(ctx, adminPathValue(ctx, "group"))
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		replyAdmin(ctx, fasthttp.StatusOK, AdminGroupMembersResponse{Members: members})
	}
}

// adminPathValue returns a path parameter, decoding any percent-encoding (for example '%40' for '@'), which the
// router leaves as it is. Usernames and group names never contain '%', so decoding can't change their meaning.
// adminActor returns the context of the request carrying the client calling the administration API as the actor which
// the audit records.
func adminActor(ctx *middlewares.AutheliaCtx) context.Context {
	return management.WithActor(ctx, "client:"+ctx.BearerClientID())
}

func adminPathValue(ctx *middlewares.AutheliaCtx, name string) string {
	value, _ := ctx.UserValue(name).(string)

	if decoded, err := url.PathUnescape(value); err == nil {
		return decoded
	}

	return value
}

func adminQueryInt(ctx *middlewares.AutheliaCtx, name string, fallback int) (value int, err error) {
	raw := ctx.QueryArgs().Peek(name)

	if len(raw) == 0 {
		return fallback, nil
	}

	if value, err = strconv.Atoi(string(raw)); err != nil {
		return 0, fmt.Errorf("%w: the query parameter '%s' must be an integer", management.ErrInvalid, name)
	}

	return value, nil
}

// decodeAdminBody decodes a JSON request body, refusing unknown fields so a misspelt field is an error rather than
// silently ignored.
func decodeAdminBody(ctx *middlewares.AutheliaCtx, value any) error {
	mediaType, _, _ := bytes.Cut(ctx.Request.Header.ContentType(), []byte(";"))

	if !bytes.EqualFold(bytes.TrimSpace(mediaType), []byte(contentTypeAdminJSON)) {
		return fmt.Errorf("%w: the request body must be JSON with the content type '%s'", management.ErrInvalid, contentTypeAdminJSON)
	}

	decoder := json.NewDecoder(bytes.NewReader(ctx.PostBody()))

	decoder.DisallowUnknownFields()

	if err := decoder.Decode(value); err != nil {
		return fmt.Errorf("%w: the request body is not valid: %v", management.ErrInvalid, err)
	}

	return nil
}

func logAdminChange(ctx *middlewares.AutheliaCtx, message string, fields ...string) {
	entry := ctx.Logger.WithField("client_id", ctx.BearerClientID())

	for i := 0; i+1 < len(fields); i += 2 {
		entry = entry.WithField(fields[i], fields[i+1])
	}

	entry.Infof("Administration API: %s", message)
}

func replyAdmin(ctx *middlewares.AutheliaCtx, status int, body any) {
	if err := ctx.ReplyJSON(body, status); err != nil {
		ctx.Logger.WithError(err).Error("Error occurred encoding JSON response.")
	}
}

// adminConflictDescription describes a conflict without the details of the storage.
func adminConflictDescription(err error) string {
	switch {
	case errors.Is(err, storage.ErrAuthenticationUsernameTaken):
		return "The username is taken."
	case errors.Is(err, storage.ErrAuthenticationUsernameDeleted):
		return "The username belonged to a deleted user and can't be used again."
	case errors.Is(err, storage.ErrAuthenticationEmailTaken):
		return "The email is taken."
	case errors.Is(err, storage.ErrAuthenticationGroupExists):
		return "The group exists already."
	case errors.Is(err, storage.ErrAuthenticationUserGroupExists):
		return "The user is a member of the group already."
	default:
		return "The request conflicts with an existing user or group."
	}
}

func replyAdminError(ctx *middlewares.AutheliaCtx, err error) {
	var (
		status int
		body   AdminErrorResponse
	)

	switch {
	case errors.Is(err, management.ErrInvalid):
		status, body = fasthttp.StatusBadRequest, AdminErrorResponse{Error: "invalid_request", ErrorDescription: err.Error()}
	// The details of a missing or conflicting user or group come from the storage, such as a signature which isn't
	// valid, so they are logged rather than returned.
	case errors.Is(err, management.ErrNotFound):
		ctx.Logger.WithError(err).WithField("client_id", ctx.BearerClientID()).Debug("Administration API request for a user or group which doesn't exist")

		status, body = fasthttp.StatusNotFound, AdminErrorResponse{Error: "not_found", ErrorDescription: "The user or group does not exist."}
	case errors.Is(err, management.ErrConflict):
		ctx.Logger.WithError(err).WithField("client_id", ctx.BearerClientID()).Debug("Administration API request conflicting with an existing user or group")

		status, body = fasthttp.StatusConflict, AdminErrorResponse{Error: "conflict", ErrorDescription: adminConflictDescription(err)}
	default:
		ctx.Logger.WithError(err).WithField("client_id", ctx.BearerClientID()).Error("Administration API request failed")

		status, body = fasthttp.StatusInternalServerError, AdminErrorResponse{Error: "server_error", ErrorDescription: "The request could not be completed. The server logs have the details."}
	}

	replyAdmin(ctx, status, body)
}
