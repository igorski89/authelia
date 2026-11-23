// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
)

// testDatabaseUserStore is an in-memory DatabaseUserStore keyed by canonical username.
type testDatabaseUserStore struct {
	users map[string]*model.AuthenticationUser
	err   error
}

func (s *testDatabaseUserStore) LoadAuthenticationUser(_ context.Context, username string) (*model.AuthenticationUser, error) {
	if s.err != nil {
		return nil, s.err
	}

	if user, ok := s.users[model.CanonicalAuthenticationUsername(username)]; ok {
		u := *user

		return &u, nil
	}

	return nil, ErrUserNotFound
}

func (s *testDatabaseUserStore) LoadAuthenticationUserByEmail(_ context.Context, email string) (*model.AuthenticationUser, error) {
	for _, user := range s.users {
		if user.Email == model.CanonicalAuthenticationUsername(email) {
			u := *user

			return &u, nil
		}
	}

	return nil, ErrUserNotFound
}

func (s *testDatabaseUserStore) UpdateAuthenticationUserPassword(_ context.Context, username, digest string) error {
	user, ok := s.users[model.CanonicalAuthenticationUsername(username)]
	if !ok {
		return ErrUserNotFound
	}

	user.Password = sql.NullString{String: digest, Valid: digest != ""}

	return nil
}

func newTestDatabaseUserProvider(t *testing.T, email bool) (*DatabaseUserProvider, *testDatabaseUserStore) {
	t.Helper()

	store := &testDatabaseUserStore{users: map[string]*model.AuthenticationUser{
		"john": {
			Username: "john", Email: "john@example.com", DisplayName: "John Smith", GivenName: "John", FamilyName: "Smith",
			// The password is 'password'.
			Password: sql.NullString{String: "$argon2id$v=19$m=64,t=1,p=1$2eqfZS5ZCxmK+sWyv5rauw$qsDFAfTl8ByCIrMMzbU6o1IVe8Ea23YCGph3rqWeIw4", Valid: true},
			Groups:   []string{"admins", "users"},
		},
		"jane":    {Username: "jane", Email: "jane@example.com", Groups: []string{}},
		"blocked": {Username: "blocked", Email: "blocked@example.com", Disabled: true, Password: sql.NullString{String: "$plaintext$password", Valid: true}},
	}}

	config := &schema.AuthenticationBackendDatabase{Password: schema.DefaultCIPasswordConfig, Search: schema.AuthenticationBackendDatabaseSearch{Email: email}}

	provider := NewDatabaseUserProvider(config, store)

	require.NoError(t, provider.StartupCheck())

	return provider, store
}

func TestDatabaseUserProviderStartupCheck(t *testing.T) {
	provider := NewDatabaseUserProvider(&schema.AuthenticationBackendDatabase{Password: schema.DefaultCIPasswordConfig}, nil)

	assert.EqualError(t, provider.StartupCheck(), "the database authentication backend requires the storage provider")
	assert.NoError(t, provider.Close())
}

func TestDatabaseUserProviderCheckUserPassword(t *testing.T) {
	provider, _ := newTestDatabaseUserProvider(t, false)

	match, err := provider.CheckUserPassword("john", "password")
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = provider.CheckUserPassword("JOHN", "password")
	assert.NoError(t, err)
	assert.True(t, match)

	match, err = provider.CheckUserPassword("john", "wrong")
	assert.NoError(t, err)
	assert.False(t, match)

	match, err = provider.CheckUserPassword("jane", "")
	assert.NoError(t, err)
	assert.False(t, match, "a user without a password never matches")

	_, err = provider.CheckUserPassword("blocked", "password")
	assert.ErrorIs(t, err, ErrUserNotFound)

	_, err = provider.CheckUserPassword("nobody", "password")
	assert.ErrorIs(t, err, ErrUserNotFound)

	_, err = provider.CheckUserPassword("john@example.com", "password")
	assert.ErrorIs(t, err, ErrUserNotFound, "email login is off by default")
}

func TestDatabaseUserProviderEmailSearch(t *testing.T) {
	provider, _ := newTestDatabaseUserProvider(t, true)

	match, err := provider.CheckUserPassword("John@Example.com", "password")
	assert.NoError(t, err)
	assert.True(t, match)

	details, err := provider.GetDetails("john@example.com")
	require.NoError(t, err)
	assert.Equal(t, "john", details.Username, "the session must carry the canonical username, not the email")

	_, err = provider.GetDetails("nobody@example.com")
	assert.ErrorIs(t, err, ErrUserNotFound)

	_, err = provider.GetDetails("blocked@example.com")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestDatabaseUserProviderGetDetails(t *testing.T) {
	provider, _ := newTestDatabaseUserProvider(t, false)

	details, err := provider.GetDetails("John")
	require.NoError(t, err)
	assert.Equal(t, &UserDetails{Username: "john", DisplayName: "John Smith", Emails: []string{"john@example.com"}, Groups: []string{"admins", "users"}}, details)

	cached, err := provider.GetDetailsCached("john")
	require.NoError(t, err)
	assert.Equal(t, details, cached)

	extended, err := provider.GetDetailsExtended("john")
	require.NoError(t, err)
	assert.Equal(t, "John", extended.GivenName)
	assert.Equal(t, "Smith", extended.FamilyName)
	assert.Equal(t, details, extended.UserDetails)

	extendedCached, err := provider.GetDetailsExtendedCached("john")
	require.NoError(t, err)
	assert.Equal(t, extended, extendedCached)

	_, err = provider.GetDetails("blocked")
	assert.ErrorIs(t, err, ErrUserNotFound)

	_, err = provider.GetDetailsExtended("nobody")
	assert.ErrorIs(t, err, ErrUserNotFound)
}

func TestDatabaseUserProviderStoreErrors(t *testing.T) {
	provider, store := newTestDatabaseUserProvider(t, true)

	store.err = fmt.Errorf("the authentication user signature is not valid: %w", ErrUserNotFound)

	_, err := provider.GetDetails("john")
	assert.ErrorIs(t, err, ErrUserNotFound, "a tampered user is reported as not found")

	store.err = errors.New("database is locked")

	_, err = provider.GetDetails("john")
	assert.EqualError(t, err, "error loading user 'john' from the database authentication backend: database is locked")
	assert.NotErrorIs(t, err, ErrUserNotFound, "an unavailable database must not look like a deleted user")

	_, err = provider.CheckUserPassword("john", "password")
	assert.NotErrorIs(t, err, ErrUserNotFound)
}

func TestDatabaseUserProviderPasswords(t *testing.T) {
	provider, store := newTestDatabaseUserProvider(t, false)

	assert.ErrorIs(t, provider.ChangePassword("john", "password", "password"), ErrPasswordWeak)
	assert.ErrorIs(t, provider.ChangePassword("john", "password", "  "), ErrPasswordWeak)
	assert.ErrorIs(t, provider.ChangePassword("john", "wrong", "new-password"), ErrIncorrectPassword)
	assert.ErrorIs(t, provider.ChangePassword("blocked", "password", "new-password"), ErrUserNotFound)

	require.NoError(t, provider.ChangePassword("John", "password", "new-password"))
	assert.True(t, strings.HasPrefix(store.users["john"].Password.String, "$"))

	match, err := provider.CheckUserPassword("john", "new-password")
	assert.NoError(t, err)
	assert.True(t, match)

	require.NoError(t, provider.UpdatePassword("jane", "jane-password"))

	match, err = provider.CheckUserPassword("jane", "jane-password")
	assert.NoError(t, err)
	assert.True(t, match)

	assert.ErrorIs(t, provider.UpdatePassword("blocked", "x"), ErrUserNotFound)
	assert.ErrorIs(t, provider.UpdatePassword("nobody", "x"), ErrUserNotFound)
}
