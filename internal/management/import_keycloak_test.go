// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// The fixture is a synthetic Keycloak 26.8.2 realm export (users and groups only) made for these tests: the passwords
// are Throwaway-<username>-pw1, and the passkeys were registered with a virtual authenticator for the RP ID localhost.
func readKeycloakFixture(t *testing.T) []byte {
	t.Helper()

	data, err := os.ReadFile("testdata/keycloak-realm-export.json")
	require.NoError(t, err)

	return data
}

func TestImportKeycloak(t *testing.T) {
	service, store := newTestService(t)
	ctx := WithActor(context.Background(), "cli:test")
	data := readKeycloakFixture(t)

	// A dry run reports everything and keeps nothing.
	report, err := service.ImportKeycloak(ctx, bytes.NewReader(data), KeycloakImportOptions{RPID: "localhost"})
	require.NoError(t, err)
	assert.False(t, report.Applied)
	assert.Equal(t, 3, report.Users)
	assert.Equal(t, 4, report.Groups)
	assert.Equal(t, 5, report.Memberships)
	assert.Equal(t, map[string]int{"argon2id": 3}, report.Passwords)
	assert.Equal(t, map[string]int{"webauthn": 3}, report.WebAuthn)

	users, err := service.ListUsers(ctx, 100, 0)
	require.NoError(t, err)
	assert.Empty(t, users)

	// The import.
	report, err = service.ImportKeycloak(ctx, bytes.NewReader(data), KeycloakImportOptions{RPID: "localhost", Apply: true})
	require.NoError(t, err)
	assert.True(t, report.Applied)

	user, err := service.GetUser(ctx, "bob-test")
	require.NoError(t, err)
	assert.Equal(t, "bob-test@example.com", user.Email)
	assert.ElementsMatch(t, []string{"admins", "forgejo_users", "sgnl_users"}, user.Groups)

	// The password hash is Keycloak's, and the known password matches it.
	row, err := store.LoadAuthenticationUser(ctx, "alice-test")
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(row.Password.String, "$argon2id$v=19$m=7168,t=5,p=1$"), row.Password.String)

	digest, err := schema.DecodePasswordDigest(row.Password.String)
	require.NoError(t, err)
	assert.True(t, digest.Match("Throwaway-alice-test-pw1"))
	assert.False(t, digest.Match("Throwaway-alice-test-pw2"))

	// The Keycloak user ID is the subject identifier and the WebAuthn user handle.
	subject, err := store.LoadUserOpaqueIdentifierBySignature(ctx, "openid", "", "carol-test")
	require.NoError(t, err)
	assert.Equal(t, "a82dd03d-ca05-46f3-a27e-ed41c79d0d69", subject.Identifier.String())

	webauthnUser, err := store.LoadWebAuthnUser(ctx, "localhost", "carol-test")
	require.NoError(t, err)
	assert.Equal(t, "a82dd03d-ca05-46f3-a27e-ed41c79d0d69", webauthnUser.UserID)

	credentials, err := store.LoadWebAuthnCredentialsByUsername(ctx, "localhost", "carol-test")
	require.NoError(t, err)
	require.Len(t, credentials, 1)
	assert.NotZero(t, credentials[0].SignCount)
	assert.NotEmpty(t, credentials[0].PublicKey)
	assert.False(t, credentials[0].Discoverable)

	imported, err := store.IsWebAuthnCredentialImported(ctx, credentials[0].KID.String())
	require.NoError(t, err)
	assert.True(t, imported)

	// The mark goes with the credential.
	alice, err := store.LoadWebAuthnCredentialsByUsername(ctx, "localhost", "alice-test")
	require.NoError(t, err)
	require.Len(t, alice, 1)
	require.NoError(t, store.DeleteWebAuthnCredential(ctx, alice[0].KID.String()))

	imported, err = store.IsWebAuthnCredentialImported(ctx, alice[0].KID.String())
	require.NoError(t, err)
	assert.False(t, imported, "the mark of a deleted credential is removed")

	imported, err = store.IsWebAuthnCredentialImported(ctx, credentials[0].KID.String())
	require.NoError(t, err)
	assert.True(t, imported, "other marks stay")

	audit, err := service.ListAudit(ctx, "alice-test", 100, 0)
	require.NoError(t, err)

	actions := make([]string, 0, len(audit))

	for _, entry := range audit {
		actions = append(actions, entry.Action)
	}

	assert.Contains(t, actions, AuditActionUserImport)

	// A second import fails, as the users exist, and changes nothing.
	_, err = service.ImportKeycloak(ctx, bytes.NewReader(data), KeycloakImportOptions{RPID: "localhost", Apply: true})
	require.Error(t, err)

	groups, err := service.ListGroups(ctx)
	require.NoError(t, err)
	assert.Len(t, groups, 4)
}

func TestImportKeycloakUnsupported(t *testing.T) {
	testCases := []struct {
		name     string
		export   string
		opts     KeycloakImportOptions
		expected string
		skipped  int
	}{
		{"ShouldRequireTheRPIDForWebAuthn", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","email":"a@example.com","enabled":true,"credentials":[{"type":"webauthn","credentialData":"{}"}]}]}`, KeycloakImportOptions{}, "the WebAuthn RP ID is required", 0},
		{"ShouldRefuseOTP", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","email":"a@example.com","enabled":true,"credentials":[{"type":"otp"}]}]}`, KeycloakImportOptions{}, "the credential type 'otp' can't be imported", 0},
		{"ShouldSkipOTP", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","email":"a@example.com","enabled":true,"credentials":[{"type":"otp"}]}]}`, KeycloakImportOptions{SkipUnsupported: true}, "", 1},
		{"ShouldRefuseSubgroups", `{"groups":[{"name":"a","path":"/a","subGroups":[{"name":"b","path":"/a/b"}]}]}`, KeycloakImportOptions{}, "can't be imported, as groups are flat", 0},
		{"ShouldRefuseNonUUIDUserID", `{"users":[{"id":"not-a-uuid","username":"a","email":"a@example.com","enabled":true}]}`, KeycloakImportOptions{}, "the user ID is not a UUID", 0},
		{"ShouldRefuseFederatedUsers", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","federationLink":"ldap"}]}`, KeycloakImportOptions{}, "federated users", 0},
		{"ShouldRefuseAnotherRPID", `{"webAuthnPolicyRpId":"id.example.com","users":[]}`, KeycloakImportOptions{RPID: "auth.example.com"}, "registered for the RP ID 'id.example.com'", 0},
		{"ShouldRefuseUsersWithoutEmail", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","enabled":true}]}`, KeycloakImportOptions{}, "user 'a'", 0},
		{"ShouldSkipUsersWithoutEmail", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","enabled":true}]}`, KeycloakImportOptions{SkipUnsupported: true}, "", 1},
		{"ShouldRefuseInvalidUsernames", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a b","email":"a@example.com","enabled":true}]}`, KeycloakImportOptions{}, "the username must", 0},
		{"ShouldIgnorePasswordHistory", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","email":"a@example.com","enabled":true,"credentials":[{"type":"password-history"}]}]}`, KeycloakImportOptions{}, "", 0},
		{"ShouldSkipServiceAccounts", `{"users":[{"id":"x","username":"service-account-app","serviceAccountClientId":"app"}]}`, KeycloakImportOptions{}, "", 1},
		{"ShouldRefuseUnknownHashes", `{"users":[{"id":"64cbf037-42cd-4a17-b555-8ee34dda4bc2","username":"a","email":"a@example.com","enabled":true,"credentials":[{"type":"password","secretData":"{\"value\":\"aGFzaA==\",\"salt\":\"c2FsdA==\"}","credentialData":"{\"hashIterations\":1,\"algorithm\":\"md5\"}"}]}]}`, KeycloakImportOptions{}, "the algorithm 'md5' is not supported", 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			service, _ := newTestService(t)

			report, err := service.ImportKeycloak(WithActor(context.Background(), "cli:test"), strings.NewReader(tc.export), tc.opts)
			if tc.expected != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.expected)

				return
			}

			require.NoError(t, err)
			assert.Len(t, report.Skipped, tc.skipped)
		})
	}
}

func TestKeycloakPBKDF2Digests(t *testing.T) {
	// Computed with Python hashlib.pbkdf2_hmac for the password "password" and the salt below.
	testCases := []struct {
		algorithm, value string
		iterations       int
		expected         string
	}{
		{"pbkdf2-sha512", "K90gij2YBNIgoz/D9Y7pzyQJqQ2BUrwnEFqwnC2/GnuEIjIZaMTyQapaiwNEy7a17KAqaJm+3CtgURDwS29PJQ==", 30000, "pbkdf2-sha512"},
		{"pbkdf2", "CAWZtnmnvFgKKs891UBlojfsrD0=", 20000, "pbkdf2-sha1"},
	}

	for _, tc := range testCases {
		t.Run(tc.algorithm, func(t *testing.T) {
			digest, algorithm, err := keycloakPasswordDigest(keycloakCredential{
				SecretData:     `{"value":"` + tc.value + `","salt":"KQ/nrX3xiiuOAoRGGXhBLQ=="}`,
				CredentialData: fmt.Sprintf(`{"hashIterations":%d,"algorithm":"%s","additionalParameters":{}}`, tc.iterations, tc.algorithm),
			})
			require.NoError(t, err)
			assert.Equal(t, tc.expected, algorithm)

			decoded, err := schema.DecodePasswordDigest(digest)
			require.NoError(t, err)
			assert.True(t, decoded.Match("password"), digest)
		})
	}
}

func TestKeycloakPBKDF2Digest(t *testing.T) {
	// PBKDF2-SHA256 with 27500 iterations of "password" (computed with Python hashlib), as Keycloak's former default stored it.
	digest, algorithm, err := keycloakPasswordDigest(keycloakCredential{ //nolint:gosec // A test hash of the password "password".
		SecretData:     `{"value":"oT+dDbkNgJVFb3CZZgE+2PqTsmGSwVkuEVfK5JvBMgs=","salt":"KQ/nrX3xiiuOAoRGGXhBLQ=="}`,
		CredentialData: `{"hashIterations":27500,"algorithm":"pbkdf2-sha256","additionalParameters":{}}`,
	})
	require.NoError(t, err)
	assert.Equal(t, "pbkdf2-sha256", algorithm)

	decoded, err := schema.DecodePasswordDigest(digest)
	require.NoError(t, err)
	assert.True(t, decoded.Match("password"), digest)
}
