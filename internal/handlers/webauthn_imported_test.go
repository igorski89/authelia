// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package handlers

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/mocks"
	"github.com/authelia/authelia/v4/internal/model"
)

func TestHandleWebAuthnAdoptImportedFlags(t *testing.T) {
	kid := model.NewBase64([]byte("credential-1"))

	response := func(be, bs bool) *protocol.ParsedCredentialAssertionData {
		var flags protocol.AuthenticatorFlags

		if be {
			flags |= protocol.FlagBackupEligible
		}

		if bs {
			flags |= protocol.FlagBackupState
		}

		r := &protocol.ParsedCredentialAssertionData{}
		r.RawID = []byte("credential-1")
		r.Response.AuthenticatorData.Flags = flags

		return r
	}

	t.Run("ShouldNotLookUpWhenTheFlagMatches", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		credentials := []model.WebAuthnCredential{{KID: kid, BackupEligible: true}}

		adopted, err := handleWebAuthnAdoptImportedFlags(mock.Ctx, credentials, response(true, true))
		require.NoError(t, err)
		assert.Equal(t, "", adopted)
	})

	t.Run("ShouldAdoptTheFlagsOfAnImportedCredential", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().IsWebAuthnCredentialImported(mock.Ctx, kid.String()).Return(true, nil)

		credentials := []model.WebAuthnCredential{{KID: kid}}

		adopted, err := handleWebAuthnAdoptImportedFlags(mock.Ctx, credentials, response(true, true))
		require.NoError(t, err)
		assert.Equal(t, kid.String(), adopted)
		assert.True(t, credentials[0].BackupEligible)
		assert.True(t, credentials[0].BackupState)
	})

	t.Run("ShouldKeepTheCheckForOtherCredentials", func(t *testing.T) {
		mock := mocks.NewMockAutheliaCtx(t)
		defer mock.Close()

		mock.StorageMock.EXPECT().IsWebAuthnCredentialImported(mock.Ctx, kid.String()).Return(false, nil)

		credentials := []model.WebAuthnCredential{{KID: kid}}

		adopted, err := handleWebAuthnAdoptImportedFlags(mock.Ctx, credentials, response(true, false))
		require.NoError(t, err)
		assert.Equal(t, "", adopted)
		assert.False(t, credentials[0].BackupEligible)
	})
}
