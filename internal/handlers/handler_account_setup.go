// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"encoding/json"
	"fmt"
	"net/mail"
	"net/url"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/valyala/fasthttp"

	"github.com/authelia/authelia/v4/internal/management"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/regulation"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/templates"
	"github.com/authelia/authelia/v4/internal/utils"
)

const (
	// accountSetupPath is the portal route of invite links.
	accountSetupPath = "account-setup"

	accountSetupMailTitle = "Set up your account"
)

// AdminUserInviteRequest is the optional body of a request to the AdminUserInvitePOST handler.
type AdminUserInviteRequest struct {
	// Lifespan is how long the link is valid, such as '72h' or '3d'.
	Lifespan string `json:"lifespan,omitempty"`
}

// AdminUserInviteResponse is the body of a successful response from the AdminUserInvitePOST handler. It never carries
// the link, which only the user receives.
type AdminUserInviteResponse struct {
	Username  string    `json:"username"`
	Email     string    `json:"email"`
	ExpiresAt time.Time `json:"expires_at"`
}

// AdminUserInvitePOST sends a user a one-time link to set a password and register a passkey, revoking the earlier
// invite links of the user.
func AdminUserInvitePOST(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		var (
			in       AdminUserInviteRequest
			lifespan time.Duration
			err      error
		)

		if len(ctx.PostBody()) != 0 {
			if err = decodeAdminBody(ctx, &in); err != nil {
				replyAdminError(ctx, err)
				return
			}
		}

		if in.Lifespan != "" {
			if lifespan, err = utils.ParseDurationString(in.Lifespan); err != nil {
				replyAdminError(ctx, fmt.Errorf("%w: the lifespan '%s' is not a duration such as '72h' or '3d'", management.ErrInvalid, in.Lifespan))
				return
			}
		}

		if len(ctx.Configuration.IdentityValidation.ResetPassword.JWTSecret) == 0 {
			replyAdminError(ctx, fmt.Errorf("invites require the 'identity_validation.reset_password.jwt_secret' option, which signs the links"))
			return
		}

		issuer, err := ctx.IssuerURL()
		if err != nil {
			replyAdminError(ctx, fmt.Errorf("error determining the issuer: %w", err))
			return
		}

		invite, err := service.CreateInvite(adminActor(ctx), adminPathValue(ctx, "username"), lifespan, ctx.RemoteIP())
		if err != nil {
			replyAdminError(ctx, err)
			return
		}

		if err = sendAccountSetupMail(ctx, issuer, invite); err != nil {
			if revokeErr := service.RevokeInvite(ctx, invite); revokeErr != nil {
				ctx.Logger.WithError(revokeErr).WithField("username", invite.User.Username).Error("Error occurred revoking an invite which could not be sent")
			}

			replyAdminError(ctx, fmt.Errorf("error sending the invite: %w", err))

			return
		}

		logAdminChange(ctx, "Invited user", "username", invite.User.Username)

		replyAdmin(ctx, fasthttp.StatusAccepted, AdminUserInviteResponse{Username: invite.User.Username, Email: invite.User.Email, ExpiresAt: invite.Verification.ExpiresAt.UTC()})
	}
}

func sendAccountSetupMail(ctx *middlewares.AutheliaCtx, issuer *url.URL, invite *management.Invite) (err error) {
	var method *jwt.SigningMethodHMAC

	switch ctx.Configuration.IdentityValidation.ResetPassword.JWTAlgorithm {
	case "HS384":
		method = jwt.SigningMethodHS384
	case "HS512":
		method = jwt.SigningMethodHS512
	default:
		method = jwt.SigningMethodHS256
	}

	token, err := jwt.NewWithClaims(method, invite.Verification.ToIdentityVerificationClaim(issuer)).SignedString([]byte(ctx.Configuration.IdentityValidation.ResetPassword.JWTSecret))
	if err != nil {
		return fmt.Errorf("error signing the invite link: %w", err)
	}

	link := &url.URL{Scheme: issuer.Scheme, Host: issuer.Host, Path: issuer.Path}

	link = link.JoinPath(accountSetupPath)

	query := link.Query()
	query.Set("token", token)
	link.RawQuery = query.Encode()

	name := invite.User.DisplayName
	if name == "" {
		name = invite.User.Username
	}

	domain, _ := ctx.GetCookieDomain()

	data := templates.EmailAccountSetupValues{
		Title:       accountSetupMailTitle,
		DisplayName: name,
		Domain:      domain,
		LinkURL:     link.String(),
		LinkText:    accountSetupMailTitle,
		Expires:     invite.Verification.ExpiresAt.UTC().Format("2006-01-02 15:04 MST"),
	}

	return ctx.Providers.Notifier.Send(ctx, mail.Address{Name: name, Address: invite.User.Email}, accountSetupMailTitle, ctx.Providers.Templates.GetAccountSetupEmailTemplate(), data)
}

// AccountSetupIdentityFinishPOST redeems an invite link, which can be used once, and lets the session set the
// password of the invited user. The user must still exist and be enabled. The identifier of the link is kept in the
// session, so revoking the link (a new invite, or disabling the user) ends a setup which was not finished yet.
func AccountSetupIdentityFinishPOST(ctx *middlewares.AutheliaCtx) {
	// The token is only read here to remember its identifier; the middleware verifies it before the setup starts.
	ctx.SetUserValue(userValueKeyAccountSetupID, identityVerificationTokenID(ctx))

	accountSetupIdentityFinishVerified(ctx)
}

const userValueKeyAccountSetupID = "account_setup_id"

var accountSetupIdentityFinishVerified = middlewares.IdentityVerificationFinish(
	middlewares.IdentityVerificationFinishArgs{
		ActionClaim: management.ActionAccountSetup,
		IsTokenUserValidFunc: func(ctx *middlewares.AutheliaCtx, username string) bool {
			_, err := ctx.Providers.UserProvider.GetDetails(username)

			return err == nil
		},
	},
	accountSetupIdentityFinish,
)

func accountSetupIdentityFinish(ctx *middlewares.AutheliaCtx, username string) {
	id, _ := ctx.UserValue(userValueKeyAccountSetupID).(string)

	if id == "" {
		ctx.GetLogger().Error("Error occurred during account setup: the invite link has no identifier")
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	userSession, err := ctx.GetSession()
	if err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred retrieving the session during account setup")
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	userSession.AccountSetupUsername = &username
	userSession.AccountSetupID = id

	if err = ctx.SaveSession(&userSession); err != nil {
		ctx.GetLogger().WithError(err).Error("Error occurred saving the session during account setup")
		ctx.SetJSONError(messageOperationFailed)

		return
	}

	ctx.ReplyOK()
}

// accountSetupLinkValid checks again that the invite link the session redeemed belongs to the user, and was neither
// revoked nor expired since.
func accountSetupLinkValid(ctx *middlewares.AutheliaCtx, id, username string) bool {
	return identityVerificationLinkValid(ctx, id, username, management.ActionAccountSetup)
}

// identityVerificationLinkValid checks again that the link a session redeemed is one for the action, belongs to the
// user, and was neither revoked nor expired since it was opened.
func identityVerificationLinkValid(ctx *middlewares.AutheliaCtx, id, username, action string) bool {
	fields := map[string]any{"username": username, "action": action}

	if id == "" {
		ctx.GetLogger().WithFields(fields).Error("Error occurred checking the link the session redeemed: the session has no link identifier")

		return false
	}

	verification, err := ctx.Providers.StorageProvider.LoadIdentityVerification(ctx, id)

	switch {
	case err != nil:
		ctx.GetLogger().WithError(err).WithFields(fields).Error("Error occurred loading the link the session redeemed")

		return false
	case verification.Action != action, verification.Username != username:
		ctx.GetLogger().WithFields(fields).Error("Error occurred checking the link the session redeemed: it does not belong to the user")

		return false
	case verification.RevokedAt.Valid:
		ctx.GetLogger().WithFields(fields).Error("Error occurred checking the link the session redeemed: it was revoked since it was opened")

		return false
	case !ctx.GetClock().Now().Before(verification.ExpiresAt):
		ctx.GetLogger().WithFields(fields).Error("Error occurred checking the link the session redeemed: it expired since it was opened")

		return false
	default:
		return true
	}
}

// identityVerificationTokenID returns the identifier of the link token in the request body, read without verifying
// it: the identity verification middleware verifies the token before the identifier is used.
func identityVerificationTokenID(ctx *middlewares.AutheliaCtx) string {
	var body middlewares.IdentityVerificationFinishBody

	if err := json.Unmarshal(ctx.PostBody(), &body); err != nil || body.Token == "" {
		return ""
	}

	claims := jwt.RegisteredClaims{}

	if _, _, err := jwt.NewParser().ParseUnverified(body.Token, &claims); err != nil {
		return ""
	}

	return claims.ID
}

const userValueKeyIdentityVerificationID = "identity_verification_id"

// AccountSetupPOST sets the password of the invited user whose link the session redeemed, then logs the user in with
// an elevated session so the portal can register a passkey right away: the link proved control of the email, which is
// what an elevation proves.
func AccountSetupPOST(service *management.Service) middlewares.RequestHandler {
	return func(ctx *middlewares.AutheliaCtx) {
		userSession, err := ctx.GetSession()
		if err != nil || userSession.AccountSetupUsername == nil {
			ctx.GetLogger().WithError(err).Error("Error occurred setting up an account as no invite link was redeemed in this session")
			ctx.SetJSONError(messageUnableToResetPassword)

			return
		}

		username := *userSession.AccountSetupUsername

		if !accountSetupLinkValid(ctx, userSession.AccountSetupID, username) {
			ctx.SetJSONError(messageUnableToResetPassword)

			return
		}

		var body resetPasswordStep2RequestBody

		if err = ctx.ParseBody(&body); err != nil {
			ctx.GetLogger().WithError(err).Error("Error occurred parsing the account setup request body")
			ctx.SetJSONError(messageUnableToResetPassword)

			return
		}

		if err = ctx.Providers.PasswordPolicy.Check(body.Password); err != nil {
			ctx.GetLogger().WithError(err).Error("Error occurred checking the password against the password policy")
			ctx.SetJSONError(messagePasswordWeak)

			return
		}

		if err = ctx.Providers.UserProvider.UpdatePassword(username, body.Password); err != nil {
			ctx.GetLogger().WithError(err).WithField("username", username).Error("Error occurred setting the password during account setup")
			ctx.SetJSONError(messageUnableToResetPassword)

			return
		}

		if err = service.AuditAccountSetup(ctx, username); err != nil {
			ctx.GetLogger().WithError(err).WithField("username", username).Error("Error occurred recording the account setup in the audit")
		}

		if err = accountSetupLogin(ctx, username); err != nil {
			ctx.GetLogger().WithError(err).WithField("username", username).Error("Error occurred logging in after the account setup")
			ctx.SetJSONError(messageOperationFailed)

			return
		}

		doMarkAuthenticationAttempt(ctx, true, regulation.NewBan(regulation.BanTypeNone, username, nil), regulation.AuthType1FA, nil)

		ctx.ReplyOK()
	}
}

// accountSetupLogin replaces the session with a first factor session of the user, elevated for the configured
// elevation lifespan.
func accountSetupLogin(ctx *middlewares.AutheliaCtx, username string) (err error) {
	var provider session.Strategy

	if provider, err = ctx.GetSessionProvider(); err != nil {
		return err
	}

	if err = provider.Destroy(ctx); err != nil {
		ctx.GetLogger().WithError(err).Trace("Failed to destroy the session during account setup")
	}

	if err = provider.Regenerate(ctx); err != nil {
		return err
	}

	now := ctx.GetClock().Now()

	userSession := provider.New(username)

	userSession.SetOneFactorPassword(now, false)

	if ctx.Configuration.AuthenticationBackend.RefreshInterval.Update() {
		userSession.RefreshTTL = now.Add(ctx.Configuration.AuthenticationBackend.RefreshInterval.Value())
	}

	userSession.Elevations.User = &session.Elevation{
		RemoteIP: ctx.RemoteIP(),
		Expires:  now.Add(ctx.Configuration.IdentityValidation.ElevatedSession.ElevationLifespan),
	}

	return provider.Save(ctx, &userSession)
}
