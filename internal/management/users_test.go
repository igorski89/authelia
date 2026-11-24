// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

type testPolicy struct{}

func (testPolicy) Check(password string) error {
	if len(password) < 8 {
		return errors.New("the password is too short")
	}

	return nil
}

func newTestService(t *testing.T) (*Service, storage.Provider) {
	t.Helper()

	config := &schema.Configuration{
		Storage: schema.Storage{
			EncryptionKey: "authelia-test-key-not-a-secret-authelia-test-key-not-a-secret",
			Local:         &schema.StorageLocal{Path: filepath.Join(t.TempDir(), "db.sqlite3")},
		},
	}

	store, err := storage.NewSQLiteProvider(config)
	require.NoError(t, err)
	require.NoError(t, store.StartupCheck())

	t.Cleanup(func() { _ = store.Close() })

	service, err := New(&schema.AuthenticationBackendDatabase{Password: schema.DefaultCIPasswordConfig}, store, testPolicy{}, nil)
	require.NoError(t, err)

	return service, store
}

func TestNewRequiresConfigAndStore(t *testing.T) {
	_, err := New(nil, nil, nil, nil)
	assert.EqualError(t, err, "the database authentication backend is not configured")

	_, err = New(&schema.AuthenticationBackendDatabase{}, nil, nil, nil)
	assert.EqualError(t, err, "the database authentication backend requires the storage provider")
}

func TestServiceUsers(t *testing.T) {
	service, store := newTestService(t)

	ctx := WithActor(context.Background(), "test")

	require.NoError(t, service.CreateGroup(ctx, "admins"))
	require.NoError(t, service.CreateGroup(ctx, "users"))

	t.Run("ShouldCreateUserWithGroupsAndHashedPassword", func(t *testing.T) {
		user, err := service.CreateUser(ctx, NewUser{
			Username: " John.Smith ", Email: "John@Example.com", DisplayName: " John Smith ", GivenName: "John", FamilyName: "Smith",
			Groups: []string{"users", "admins"}, Password: Password{Plain: "a-long-password"},
		})
		require.NoError(t, err)

		assert.Equal(t, "john.smith", user.Username)
		assert.Equal(t, "john@example.com", user.Email)
		assert.Equal(t, "John Smith", user.DisplayName)
		assert.Equal(t, []string{"admins", "users"}, user.Groups)
		assert.True(t, user.HasPassword)

		row, err := store.LoadAuthenticationUser(ctx, "john.smith")
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(row.Password.String, "$argon2id$"))

		data, err := json.Marshal(user)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "argon2", "the API representation never carries the digest")
	})

	t.Run("ShouldCreateUserWithDigestAndWithoutPassword", func(t *testing.T) {
		user, err := service.CreateUser(ctx, NewUser{Username: "imported", Email: "imported@example.com",
			Password: Password{Digest: "$argon2id$v=19$m=7168,t=5,p=1$c2FsdHNhbHRzYWx0c2FsdA$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFzaGhhc2g"}})
		require.NoError(t, err)
		assert.True(t, user.HasPassword)

		user, err = service.CreateUser(ctx, NewUser{Username: "invited", Email: "invited@example.com"})
		require.NoError(t, err)
		assert.False(t, user.HasPassword)
		assert.Equal(t, []string{}, user.Groups)
	})

	t.Run("ShouldRefuseInvalidUsers", func(t *testing.T) {
		testCases := []struct {
			name string
			user NewUser
		}{
			{"EmptyUsername", NewUser{Email: "a@example.com"}},
			{"UsernameWithSpace", NewUser{Username: "a b", Email: "a@example.com"}},
			{"UsernameStartingWithDot", NewUser{Username: ".a", Email: "a@example.com"}},
			{"UsernameTooLong", NewUser{Username: strings.Repeat("a", 101), Email: "a@example.com"}},
			{"EmptyEmail", NewUser{Username: "a"}},
			{"InvalidEmail", NewUser{Username: "a", Email: "not-an-email"}},
			{"EmailWithName", NewUser{Username: "a", Email: "A <a@example.com>"}},
			{"InvalidGroup", NewUser{Username: "a", Email: "a@example.com", Groups: []string{"no spaces"}}},
			{"WeakPassword", NewUser{Username: "a", Email: "a@example.com", Password: Password{Plain: "short"}}},
			{"BadDigest", NewUser{Username: "a", Email: "a@example.com", Password: Password{Digest: "plain-text"}}},
			{"PlaintextDigest", NewUser{Username: "a", Email: "a@example.com", Password: Password{Digest: "$plaintext$a-long-password"}}},
			{"Base64Digest", NewUser{Username: "a", Email: "a@example.com", Password: Password{Digest: "$base64$YS1sb25nLXBhc3N3b3Jk"}}},
			{"CryptPrefixedPlaintextDigest", NewUser{Username: "a", Email: "a@example.com", Password: Password{Digest: "{CRYPT}$plaintext$a-long-password"}}},
			{"CryptPrefixedBase64Digest", NewUser{Username: "a", Email: "a@example.com", Password: Password{Digest: "{CRYPT}$base64$YS1sb25nLXBhc3N3b3Jk"}}},
			{"BothPasswords", NewUser{Username: "a", Email: "a@example.com", Password: Password{Plain: "a-long-password", Digest: "$plaintext$x"}}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				_, err := service.CreateUser(ctx, tc.user)
				assert.ErrorIs(t, err, ErrInvalid)
			})
		}

		_, err := service.GetUser(ctx, "a")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("ShouldRefuseConflictsAndMissingGroupsAtomically", func(t *testing.T) {
		_, err := service.CreateUser(ctx, NewUser{Username: "JOHN.SMITH", Email: "other@example.com"})
		assert.ErrorIs(t, err, ErrConflict)

		_, err = service.CreateUser(ctx, NewUser{Username: "johnny", Email: "john@example.com"})
		assert.ErrorIs(t, err, ErrConflict)

		_, err = service.CreateUser(ctx, NewUser{Username: "orphan", Email: "orphan@example.com", Groups: []string{"users", "missing"}})
		assert.ErrorIs(t, err, ErrNotFound)

		_, err = service.GetUser(ctx, "orphan")
		assert.ErrorIs(t, err, ErrNotFound, "the user is not created when a group is missing")
	})

	t.Run("ShouldUpdateAndDisableUser", func(t *testing.T) {
		email, disabled := "j.smith@example.com", true

		user, err := service.UpdateUser(ctx, "John.Smith", UserChanges{Email: &email, Disabled: &disabled})
		require.NoError(t, err)

		assert.Equal(t, "j.smith@example.com", user.Email)
		assert.Equal(t, "John Smith", user.DisplayName, "fields which are not given are kept")
		assert.True(t, user.Disabled)

		bad := "nope"
		_, err = service.UpdateUser(ctx, "john.smith", UserChanges{Email: &bad})
		assert.ErrorIs(t, err, ErrInvalid)

		taken := "invited@example.com"
		_, err = service.UpdateUser(ctx, "john.smith", UserChanges{Email: &taken})
		assert.ErrorIs(t, err, ErrConflict)

		_, err = service.UpdateUser(ctx, "nobody", UserChanges{})
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("ShouldSetAndRemovePassword", func(t *testing.T) {
		require.NoError(t, service.SetPassword(ctx, "invited", Password{Plain: "another-long-password"}))

		user, err := service.GetUser(ctx, "invited")
		require.NoError(t, err)
		assert.True(t, user.HasPassword)

		require.NoError(t, service.SetPassword(ctx, "invited", Password{}))

		user, err = service.GetUser(ctx, "invited")
		require.NoError(t, err)
		assert.False(t, user.HasPassword)

		assert.ErrorIs(t, service.SetPassword(ctx, "invited", Password{Plain: "short"}), ErrInvalid)
		assert.ErrorIs(t, service.SetPassword(ctx, "nobody", Password{}), ErrNotFound)
	})

	t.Run("ShouldListUsersInPages", func(t *testing.T) {
		users, err := service.ListUsers(ctx, 0, 0)
		require.NoError(t, err)
		require.Len(t, users, 3)
		assert.Equal(t, "imported", users[0].Username)

		users, err = service.ListUsers(ctx, 2, 1)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "john.smith", users[0].Username)

		_, err = service.ListUsers(ctx, MaxPageSize+1, 0)
		assert.ErrorIs(t, err, ErrInvalid)

		_, err = service.ListUsers(ctx, 10, -1)
		assert.ErrorIs(t, err, ErrInvalid)
	})

	t.Run("ShouldManageGroups", func(t *testing.T) {
		assert.ErrorIs(t, service.CreateGroup(ctx, "admins"), ErrConflict)
		assert.ErrorIs(t, service.CreateGroup(ctx, "bad name"), ErrInvalid)

		require.NoError(t, service.AddUserToGroup(ctx, "invited", "users"))
		assert.ErrorIs(t, service.AddUserToGroup(ctx, "invited", "users"), ErrConflict)
		assert.ErrorIs(t, service.AddUserToGroup(ctx, "invited", "missing"), ErrNotFound)

		members, err := service.GroupMembers(ctx, "users")
		require.NoError(t, err)
		require.Len(t, members, 2)
		assert.Equal(t, "invited", members[0].Username)
		assert.Equal(t, "john.smith", members[1].Username)
		assert.Equal(t, "invited@example.com", members[0].Email)

		require.NoError(t, service.RemoveUserFromGroup(ctx, "invited", "users"))

		groups, err := service.ListGroups(ctx)
		require.NoError(t, err)
		require.Len(t, groups, 2)
		assert.Equal(t, "admins", groups[0].Name)

		require.NoError(t, service.DeleteGroup(ctx, "admins"))
		assert.ErrorIs(t, service.DeleteGroup(ctx, "admins"), ErrNotFound)

		_, err = service.GroupMembers(ctx, "admins")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("ShouldDeleteUserWithSecondFactorsAndNeverReuseUsername", func(t *testing.T) {
		require.NoError(t, store.SaveTOTPConfiguration(ctx, model.TOTPConfiguration{
			CreatedAt: time.Now(), Username: "john.smith", Issuer: "Authelia", Algorithm: "SHA1", Digits: 6, Period: 30, Secret: []byte("secret"),
		}))
		require.NoError(t, store.SaveWebAuthnCredential(ctx, model.WebAuthnCredential{
			CreatedAt: time.Now(), RPID: "example.com", Username: "john.smith", Description: "key", KID: model.NewBase64([]byte("kid")),
			AttestationType: "none", PublicKey: []byte("key"), Discoverable: true,
		}))

		require.NoError(t, service.DeleteUser(ctx, "John.Smith"))

		_, err := service.GetUser(ctx, "john.smith")
		assert.ErrorIs(t, err, ErrNotFound)

		_, err = store.LoadTOTPConfiguration(ctx, "john.smith")
		assert.Error(t, err)

		credentials, err := store.LoadWebAuthnCredentialsByUsername(ctx, "example.com", "john.smith")
		require.NoError(t, err)
		assert.Empty(t, credentials)

		_, err = service.CreateUser(ctx, NewUser{Username: "john.smith", Email: "new@example.com"})
		assert.ErrorIs(t, err, ErrConflict)

		assert.ErrorIs(t, service.DeleteUser(ctx, "john.smith"), ErrNotFound)
	})
}

type testSessions struct {
	sessions map[string]int
}

func (s *testSessions) CountByUsername(_ context.Context, username string) (int, error) {
	return s.sessions[username], nil
}

func (s *testSessions) DestroyByUsername(_ context.Context, username string) (int, error) {
	n := s.sessions[username]

	delete(s.sessions, username)

	return n, nil
}

func TestServiceRevokeUser(t *testing.T) {
	_, store := newTestService(t)

	sessions := &testSessions{sessions: map[string]int{"john": 2, "jane": 1}}

	service, err := New(&schema.AuthenticationBackendDatabase{Password: schema.DefaultCIPasswordConfig}, store, nil, sessions)
	require.NoError(t, err)

	ctx := WithActor(context.Background(), "test")

	_, err = service.CreateUser(ctx, NewUser{Username: "john", Email: "john@example.com"})
	require.NoError(t, err)

	_, err = service.CreateUser(ctx, NewUser{Username: "jane", Email: "jane@example.com"})
	require.NoError(t, err)

	user, err := service.GetUser(ctx, "john")
	require.NoError(t, err)
	require.NotNil(t, user.Sessions)
	assert.Equal(t, 2, *user.Sessions)
	assert.Equal(t, []string{}, user.Credentials)

	revocation, err := service.RevokeUser(ctx, "john", "app")
	require.NoError(t, err)
	assert.Nil(t, revocation.Sessions, "revoking one client keeps the portal sessions")
	assert.Equal(t, 2, sessions.sessions["john"])

	revocation, err = service.RevokeUser(ctx, "JOHN", "")
	require.NoError(t, err)
	require.NotNil(t, revocation.Sessions)
	assert.Equal(t, 2, *revocation.Sessions)

	_, err = service.RevokeUser(ctx, "not valid", "")
	assert.ErrorIs(t, err, ErrInvalid)

	disabled := true

	_, err = service.UpdateUser(ctx, "jane", UserChanges{Disabled: &disabled})
	require.NoError(t, err)
	assert.Equal(t, 0, sessions.sessions["jane"], "disabling a user ends its sessions")

	sessions.sessions["john"] = 3

	require.NoError(t, service.DeleteUser(ctx, "john"))
	assert.Equal(t, 0, sessions.sessions["john"], "deleting a user ends its sessions")
}
