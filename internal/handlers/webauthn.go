// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"bytes"
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/random"
)

const (
	webauthnCredentialDescriptionMaxLen = 64
)

func handleGetWebAuthnUserByRPID(ctx *middlewares.AutheliaCtx, username, displayname string, rpid string) (user *model.WebAuthnUser, err error) {
	if user, err = ctx.Providers.StorageProvider.LoadWebAuthnUser(ctx, rpid, username); err != nil {
		return nil, err
	}

	if user == nil {
		user = &model.WebAuthnUser{
			RPID:        rpid,
			Username:    username,
			UserID:      ctx.Providers.Random.StringCustom(64, random.CharSetASCII),
			DisplayName: displayname,
		}

		if err = ctx.Providers.StorageProvider.SaveWebAuthnUser(ctx, *user); err != nil {
			return nil, err
		}
	} else {
		user.DisplayName = displayname
	}

	if user.DisplayName == "" {
		user.DisplayName = user.Username
	}

	if user.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnCredentialsByUsername(ctx, rpid, user.Username); err != nil {
		return nil, err
	}

	return user, nil
}

func handlerWebAuthnDiscoverableLogin(ctx *middlewares.AutheliaCtx, rpid string, response *protocol.ParsedCredentialAssertionData, adopted *string) webauthn.DiscoverableUserHandler {
	return func(rawID, userHandle []byte) (user webauthn.User, err error) {
		var u *model.WebAuthnUser

		if u, err = ctx.Providers.StorageProvider.LoadWebAuthnUserByUserID(ctx, rpid, string(userHandle)); err != nil {
			return nil, err
		} else if u == nil {
			return nil, fmt.Errorf("user not found")
		}

		if ctx.Configuration.WebAuthn.EnablePasskeyUpgrade {
			if u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnCredentialsByUsername(ctx, rpid, u.Username); err != nil {
				return nil, err
			}
		} else {
			if u.Credentials, err = ctx.Providers.StorageProvider.LoadWebAuthnPasskeyCredentialsByUsername(ctx, rpid, u.Username); err != nil {
				return nil, err
			}
		}

		if *adopted, err = handleWebAuthnAdoptImportedFlags(ctx, u.Credentials, response); err != nil {
			return nil, err
		}

		return u, nil
	}
}

// handleWebAuthnAdoptImportedFlags gives an imported credential, whose backup eligible and backup state flags the
// system it came from didn't keep, the flags of the assertion being validated, so the validation of the backup eligible
// flag doesn't refuse it. The assertion's signature covers the flags, and nothing is kept if the validation fails. A
// credential whose stored flag already matches keeps its mark, which only ever allows this one adoption.
// Other credentials keep the check. It returns the credential ID of the imported credential, for its mark to be removed
// once the flags are saved.
func handleWebAuthnAdoptImportedFlags(ctx *middlewares.AutheliaCtx, credentials []model.WebAuthnCredential, response *protocol.ParsedCredentialAssertionData) (kid string, err error) {
	if response == nil {
		return "", nil
	}

	flags := response.Response.AuthenticatorData.Flags

	for i := range credentials {
		if !bytes.Equal(credentials[i].KID.Bytes(), response.RawID) {
			continue
		}

		// Only a differing backup eligible flag would be refused, so only then is the mark looked up.
		if credentials[i].BackupEligible == flags.HasBackupEligible() {
			return "", nil
		}

		var imported bool

		if imported, err = ctx.Providers.StorageProvider.IsWebAuthnCredentialImported(ctx, credentials[i].KID.String()); err != nil || !imported {
			return "", err
		}

		credentials[i].BackupEligible, credentials[i].BackupState = flags.HasBackupEligible(), flags.HasBackupState()

		return credentials[i].KID.String(), nil
	}

	return "", nil
}

// handleWebAuthnImportedFlagsSaved removes the import mark of a credential whose flags were adopted and saved. A failure
// only means the flags are adopted again at the next sign in.
func handleWebAuthnImportedFlagsSaved(ctx *middlewares.AutheliaCtx, kid string) {
	if kid == "" {
		return
	}

	if err := ctx.Providers.StorageProvider.DeleteWebAuthnCredentialImported(ctx, kid); err != nil {
		ctx.GetLogger().WithError(err).Warn("Error occurred removing the import mark of a WebAuthn credential")

		return
	}

	ctx.GetLogger().WithField("kid", kid).Debug("Adopted the backup flags of an imported WebAuthn credential")
}
