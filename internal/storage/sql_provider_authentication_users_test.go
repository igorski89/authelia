// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/model"
)

func newTestAuthenticationUser(username, email string) model.AuthenticationUser {
	return model.AuthenticationUser{
		Username:    username,
		Email:       email,
		DisplayName: "John Smith",
		GivenName:   "John",
		FamilyName:  "Smith",
		Password:    sql.NullString{String: "$argon2id$v=19$m=7168,t=5,p=1$c2FsdA$aGFzaA", Valid: true},
	}
}

func TestSQLProviderAuthenticationUsers(t *testing.T) {
	provider := newTestSQLiteProvider(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	t.Run("ShouldCreateAndLoadUserInCanonicalForm", func(t *testing.T) {
		require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser(" John ", "John@Example.com")))

		user, err := provider.LoadAuthenticationUser(ctx, "JOHN")
		require.NoError(t, err)

		assert.Equal(t, "john", user.Username)
		assert.Equal(t, "john@example.com", user.Email)
		assert.Equal(t, "John Smith", user.DisplayName)
		assert.True(t, user.HasPassword())
		assert.False(t, user.Disabled)
		assert.Equal(t, []string{}, user.Groups)
		assert.False(t, user.CreatedAt.IsZero())

		byEmail, err := provider.LoadAuthenticationUserByEmail(ctx, " JOHN@example.COM")
		require.NoError(t, err)
		assert.Equal(t, user.ID, byEmail.ID)
	})

	t.Run("ShouldReturnNoUser", func(t *testing.T) {
		_, err := provider.LoadAuthenticationUser(ctx, "nobody")
		assert.ErrorIs(t, err, ErrNoAuthenticationUser)

		_, err = provider.LoadAuthenticationUserByEmail(ctx, "nobody@example.com")
		assert.ErrorIs(t, err, ErrNoAuthenticationUser)
	})

	t.Run("ShouldRefuseTakenUsernameAndEmail", func(t *testing.T) {
		assert.ErrorIs(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("JOHN", "other@example.com")), ErrAuthenticationUsernameTaken)
		assert.ErrorIs(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("johnny", "john@EXAMPLE.com")), ErrAuthenticationEmailTaken)
	})

	t.Run("ShouldRefuseEmptyUsernameOrEmail", func(t *testing.T) {
		assert.Error(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser(" ", "x@example.com")))
		assert.Error(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("x", "")))
	})

	t.Run("ShouldUpdateProfilePasswordAndDisabled", func(t *testing.T) {
		require.NoError(t, provider.UpdateAuthenticationUserProfile(ctx, "john", "J.Smith@Example.com", "J Smith", "J", "Smith"))
		require.NoError(t, provider.UpdateAuthenticationUserPassword(ctx, "john", ""))
		require.NoError(t, provider.UpdateAuthenticationUserDisabled(ctx, "john", true))

		user, err := provider.LoadAuthenticationUser(ctx, "john")
		require.NoError(t, err)

		assert.Equal(t, "j.smith@example.com", user.Email)
		assert.Equal(t, "J Smith", user.DisplayName)
		assert.False(t, user.HasPassword())
		assert.False(t, user.Password.Valid)
		assert.True(t, user.Disabled)

		require.NoError(t, provider.UpdateAuthenticationUserDisabled(ctx, "john", false))
		require.NoError(t, provider.UpdateAuthenticationUserPassword(ctx, "john", "$plaintext$secret"))
	})

	t.Run("ShouldRefuseEmailOfAnotherUser", func(t *testing.T) {
		require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("jane", "jane@example.com")))

		assert.ErrorIs(t, provider.UpdateAuthenticationUserProfile(ctx, "jane", "j.smith@example.com", "", "", ""), ErrAuthenticationEmailTaken)
		assert.NoError(t, provider.UpdateAuthenticationUserProfile(ctx, "jane", "JANE@example.com", "Jane", "", ""))
	})

	t.Run("ShouldRefuseUpdateOfMissingUser", func(t *testing.T) {
		assert.ErrorIs(t, provider.UpdateAuthenticationUserDisabled(ctx, "nobody", true), ErrNoAuthenticationUser)
	})

	t.Run("ShouldManageGroupsAndMemberships", func(t *testing.T) {
		require.NoError(t, provider.CreateAuthenticationGroup(ctx, "admins"))
		require.NoError(t, provider.CreateAuthenticationGroup(ctx, "users"))
		assert.ErrorIs(t, provider.CreateAuthenticationGroup(ctx, "admins"), ErrAuthenticationGroupExists)

		require.NoError(t, provider.AddAuthenticationUserGroup(ctx, "john", "users"))
		require.NoError(t, provider.AddAuthenticationUserGroup(ctx, "JOHN", "admins"))
		require.NoError(t, provider.AddAuthenticationUserGroup(ctx, "jane", "users"))
		assert.ErrorIs(t, provider.AddAuthenticationUserGroup(ctx, "john", "users"), ErrAuthenticationUserGroupExists)
		assert.ErrorIs(t, provider.AddAuthenticationUserGroup(ctx, "john", "missing"), ErrNoAuthenticationGroup)
		assert.ErrorIs(t, provider.AddAuthenticationUserGroup(ctx, "nobody", "users"), ErrNoAuthenticationUser)

		user, err := provider.LoadAuthenticationUser(ctx, "john")
		require.NoError(t, err)
		assert.Equal(t, []string{"admins", "users"}, user.Groups)

		members, err := provider.LoadAuthenticationGroupMembers(ctx, "users")
		require.NoError(t, err)
		assert.Equal(t, []string{"jane", "john"}, members)

		require.NoError(t, provider.RemoveAuthenticationUserGroup(ctx, "john", "admins"))

		user, err = provider.LoadAuthenticationUser(ctx, "john")
		require.NoError(t, err)
		assert.Equal(t, []string{"users"}, user.Groups)

		groups, err := provider.LoadAuthenticationGroups(ctx)
		require.NoError(t, err)
		require.Len(t, groups, 2)
		assert.Equal(t, "admins", groups[0].Name)
	})

	t.Run("ShouldListUsersInPages", func(t *testing.T) {
		users, err := provider.LoadAuthenticationUsers(ctx, 1, 0)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "jane", users[0].Username)
		assert.Equal(t, []string{"users"}, users[0].Groups)

		users, err = provider.LoadAuthenticationUsers(ctx, 1, 1)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "john", users[0].Username)

		users, err = provider.LoadAuthenticationUsers(ctx, 10, 1)
		require.NoError(t, err)
		assert.Len(t, users, 0)
	})

	t.Run("ShouldTreatTamperedUserAsInvalid", func(t *testing.T) {
		_, err := provider.db.ExecContext(ctx, "UPDATE authentication_users SET password = '$plaintext$attacker' WHERE username = 'jane';")
		require.NoError(t, err)

		_, err = provider.LoadAuthenticationUser(ctx, "jane")
		assert.ErrorIs(t, err, ErrAuthenticationUserSignatureInvalid)

		users, err := provider.LoadAuthenticationUsers(ctx, 10, 0)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, "john", users[0].Username)

		assert.ErrorIs(t, provider.UpdateAuthenticationUserDisabled(ctx, "jane", false), ErrAuthenticationUserSignatureInvalid)
		assert.ErrorIs(t, provider.AddAuthenticationUserGroup(ctx, "jane", "admins"), ErrAuthenticationUserSignatureInvalid)
		assert.ErrorIs(t, provider.SchemaEncryptionRotateHMACKey(ctx, hmacNameAuthenticationUser), ErrAuthenticationUserSignatureInvalid)
	})

	t.Run("ShouldIgnoreForgedMembership", func(t *testing.T) {
		_, err := provider.db.ExecContext(ctx, `INSERT INTO authentication_user_groups (user_id, group_id, signature)
			SELECT u.id, g.id, 'forged' FROM authentication_users u, authentication_groups g
			WHERE u.username = 'john' AND g.name = 'admins';`)
		require.NoError(t, err)

		user, err := provider.LoadAuthenticationUser(ctx, "john")
		require.NoError(t, err)
		assert.Equal(t, []string{"users"}, user.Groups)

		members, err := provider.LoadAuthenticationGroupMembers(ctx, "admins")
		require.NoError(t, err)
		assert.Empty(t, members)

		require.NoError(t, provider.RemoveAuthenticationUserGroup(ctx, "john", "admins"))
	})

	t.Run("ShouldDeleteUserAndNeverReuseUsername", func(t *testing.T) {
		require.NoError(t, provider.DeleteAuthenticationUser(ctx, "Jane"))

		_, err := provider.LoadAuthenticationUser(ctx, "jane")
		assert.ErrorIs(t, err, ErrNoAuthenticationUser)

		members, err := provider.LoadAuthenticationGroupMembers(ctx, "users")
		require.NoError(t, err)
		assert.Equal(t, []string{"john"}, members)

		var count int

		require.NoError(t, provider.db.GetContext(ctx, &count, "SELECT COUNT(*) FROM authentication_user_groups;"))
		assert.Equal(t, 1, count)

		assert.ErrorIs(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("JANE", "jane.new@example.com")), ErrAuthenticationUsernameDeleted)
		assert.ErrorIs(t, provider.DeleteAuthenticationUser(ctx, "jane"), ErrNoAuthenticationUser)

		require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("jane2", "jane@example.com")))
	})

	t.Run("ShouldRotateKeyAndSignEverythingAgain", func(t *testing.T) {
		previous := provider.keys.authenticationUserHMAC

		require.NoError(t, provider.SchemaEncryptionRotateHMACKey(ctx, hmacNameAuthenticationUser))
		assert.NotEqual(t, previous, provider.keys.authenticationUserHMAC)

		user, err := provider.LoadAuthenticationUser(ctx, "john")
		require.NoError(t, err)
		assert.Equal(t, []string{"users"}, user.Groups)

		_, err = provider.LoadAuthenticationUser(ctx, "jane2")
		require.NoError(t, err)

		key, err := provider.getHMACAuthenticationUser(ctx)
		require.NoError(t, err)
		assert.Equal(t, provider.keys.authenticationUserHMAC, key)
	})

	t.Run("ShouldDeleteGroupAndItsMemberships", func(t *testing.T) {
		require.NoError(t, provider.DeleteAuthenticationGroup(ctx, "users"))
		assert.ErrorIs(t, provider.DeleteAuthenticationGroup(ctx, "users"), ErrNoAuthenticationGroup)

		user, err := provider.LoadAuthenticationUser(ctx, "john")
		require.NoError(t, err)
		assert.Empty(t, user.Groups)

		_, err = provider.LoadAuthenticationGroupMembers(ctx, "users")
		assert.ErrorIs(t, err, ErrNoAuthenticationGroup)
	})

	t.Run("ShouldUseTransactionFromContext", func(t *testing.T) {
		txctx, err := provider.BeginTX(ctx)
		require.NoError(t, err)

		require.NoError(t, provider.CreateAuthenticationUser(txctx, newTestAuthenticationUser("rolled", "rolled@example.com")))
		require.NoError(t, provider.Rollback(txctx))

		_, err = provider.LoadAuthenticationUser(ctx, "rolled")
		assert.ErrorIs(t, err, ErrNoAuthenticationUser)
	})
}

func TestAuthenticationUserSignatureCoversEveryField(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	base := newTestAuthenticationUser("john", "john@example.com")
	signature := authenticationUserSignature(key, &base)

	changes := map[string]func(u *model.AuthenticationUser){
		"Username":    func(u *model.AuthenticationUser) { u.Username = "jane" },
		"Email":       func(u *model.AuthenticationUser) { u.Email = "jane@example.com" },
		"DisplayName": func(u *model.AuthenticationUser) { u.DisplayName = "Jane" },
		"GivenName":   func(u *model.AuthenticationUser) { u.GivenName = "Jane" },
		"FamilyName":  func(u *model.AuthenticationUser) { u.FamilyName = "Doe" },
		"Password":    func(u *model.AuthenticationUser) { u.Password.String = "$plaintext$x" },
		"PasswordNull": func(u *model.AuthenticationUser) {
			u.Password = sql.NullString{}
		},
		"Disabled": func(u *model.AuthenticationUser) { u.Disabled = true },
	}

	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			user := base
			change(&user)

			assert.NotEqual(t, signature, authenticationUserSignature(key, &user))
		})
	}

	assert.NotEqual(t, signature, authenticationUserSignature([]byte("another-key-another-key-another-k"), &base))

	membership := model.AuthenticationUserGroup{Username: "john", Group: "admins"}
	assert.NotEqual(t, authenticationUserGroupSignature(key, &membership), authenticationUserGroupSignature(key, &model.AuthenticationUserGroup{Username: "john", Group: "admin"}))
	assert.NotEqual(t, authenticationUserGroupSignature(key, &membership), authenticationUserGroupSignature(key, &model.AuthenticationUserGroup{Username: "johnadmins"}))
}

func TestSQLProviderAuthenticationUsersWithoutStartupCheck(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db.sqlite3")

	ctx := context.Background()

	migrated := newTestSQLiteProviderAtPath(t, path)
	require.NoError(t, migrated.SchemaMigrate(ctx, true, SchemaLatest))
	require.NoError(t, migrated.Close())

	// The storage commands never run the startup check, so the key is loaded on demand.
	cli := newTestSQLiteProviderAtPath(t, path)
	require.Empty(t, cli.keys.authenticationUserHMAC)
	require.NoError(t, cli.CreateAuthenticationUser(ctx, newTestAuthenticationUser("john", "john@example.com")))
	require.NoError(t, cli.CreateAuthenticationGroup(ctx, "admins"))
	require.NoError(t, cli.AddAuthenticationUserGroup(ctx, "john", "admins"))
	require.NotEmpty(t, cli.keys.authenticationUserHMAC)
	require.NoError(t, cli.Close())

	server := newTestSQLiteProviderAtPath(t, path)
	require.NoError(t, server.StartupCheck())

	user, err := server.LoadAuthenticationUser(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, []string{"admins"}, user.Groups)

	// A provider which has not loaded the key refuses to load it inside a transaction.
	fresh := newTestSQLiteProviderAtPath(t, path)

	txctx, err := fresh.BeginTX(ctx)
	require.NoError(t, err)

	assert.ErrorContains(t, fresh.CreateAuthenticationUser(txctx, newTestAuthenticationUser("jane", "jane@example.com")), "must be loaded with LoadAuthenticationUserHMACKey")
	require.NoError(t, fresh.Rollback(txctx))

	require.NoError(t, fresh.LoadAuthenticationUserHMACKey(ctx))

	txctx, err = fresh.BeginTX(ctx)
	require.NoError(t, err)
	require.NoError(t, fresh.CreateAuthenticationUser(txctx, newTestAuthenticationUser("jane", "jane@example.com")))
	require.NoError(t, fresh.Commit(txctx))
}

func TestSQLProviderAuthenticationUsernameEmailCollisions(t *testing.T) {
	provider := newTestSQLiteProvider(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("john", "john@example.com")))
	require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("jane@example.com", "jane@example.com")), "a username may equal the user's own email")

	assert.ErrorIs(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("john@example.com", "other@example.com")), ErrAuthenticationUsernameTaken, "a username must not be another user's email")
	assert.ErrorIs(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("bob", "jane@example.com")), ErrAuthenticationEmailTaken)
	assert.ErrorIs(t, provider.UpdateAuthenticationUserProfile(ctx, "john", "jane@example.com", "", "", ""), ErrAuthenticationEmailTaken, "an email must not be another user's username")

	require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("bob", "bob@example.com")))
	assert.ErrorIs(t, provider.UpdateAuthenticationUserProfile(ctx, "bob", "john", "", "", ""), ErrAuthenticationEmailTaken)

	_, err := provider.LoadAuthenticationUser(ctx, "nobody")
	assert.ErrorIs(t, err, authentication.ErrUserNotFound)

	_, err = provider.db.ExecContext(ctx, "UPDATE authentication_users SET disabled = TRUE WHERE username = 'bob';")
	require.NoError(t, err)

	_, err = provider.LoadAuthenticationUser(ctx, "bob")
	assert.ErrorIs(t, err, authentication.ErrUserNotFound, "a tampered user is reported as not found")
}

func TestSQLProviderAuthenticationGroupsSortedByteWise(t *testing.T) {
	provider := newTestSQLiteProvider(t)
	require.NoError(t, provider.StartupCheck())

	ctx := context.Background()

	require.NoError(t, provider.CreateAuthenticationUser(ctx, newTestAuthenticationUser("john", "john@example.com")))

	for _, group := range []string{"admins", "Users", "beta"} {
		require.NoError(t, provider.CreateAuthenticationGroup(ctx, group))
		require.NoError(t, provider.AddAuthenticationUserGroup(ctx, "john", group))
	}

	user, err := provider.LoadAuthenticationUser(ctx, "john")
	require.NoError(t, err)
	assert.Equal(t, []string{"Users", "admins", "beta"}, user.Groups)

	groups, err := provider.LoadAuthenticationGroups(ctx)
	require.NoError(t, err)
	require.Len(t, groups, 3)
	assert.Equal(t, "Users", groups[0].Name)
}
