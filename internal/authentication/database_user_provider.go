// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package authentication

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/go-crypt/crypt/algorithm"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/logging"
	"github.com/authelia/authelia/v4/internal/model"
)

// DatabaseUserStore is the part of the storage provider the database authentication backend uses. A user which does
// not exist is reported with an error matching ErrUserNotFound.
type DatabaseUserStore interface {
	LoadAuthenticationUser(ctx context.Context, username string) (user *model.AuthenticationUser, err error)
	LoadAuthenticationUserByEmail(ctx context.Context, email string) (user *model.AuthenticationUser, err error)
	UpdateAuthenticationUserPassword(ctx context.Context, username, digest string) (err error)
}

// databaseUserProviderTimeout bounds every storage call, as the UserProvider interface carries no context.
const databaseUserProviderTimeout = 30 * time.Second

// DatabaseUserProvider is a UserProvider which keeps users and groups in the storage database.
type DatabaseUserProvider struct {
	config *schema.AuthenticationBackendDatabase
	store  DatabaseUserStore
	hash   algorithm.Hash
}

// NewDatabaseUserProvider creates a new DatabaseUserProvider.
func NewDatabaseUserProvider(config *schema.AuthenticationBackendDatabase, store DatabaseUserStore) (provider *DatabaseUserProvider) {
	return &DatabaseUserProvider{
		config: config,
		store:  store,
	}
}

// StartupCheck implements the startup check provider interface.
func (p *DatabaseUserProvider) StartupCheck() (err error) {
	if p.store == nil {
		return fmt.Errorf("the database authentication backend requires the storage provider")
	}

	if p.hash, err = NewFileCryptoHashFromConfig(p.config.Password); err != nil {
		return err
	}

	return nil
}

// Close the provider.
func (p *DatabaseUserProvider) Close() (err error) {
	return nil
}

// CheckUserPassword checks if provided password matches for the given user.
func (p *DatabaseUserProvider) CheckUserPassword(username string, password string) (match bool, err error) {
	var user *model.AuthenticationUser

	if user, err = p.load(username); err != nil {
		return false, err
	}

	if !user.HasPassword() {
		return false, nil
	}

	var digest *schema.PasswordDigest

	if digest, err = schema.DecodePasswordDigest(user.Password.String); err != nil {
		return false, fmt.Errorf("error decoding the password digest of user '%s': %w", user.Username, err)
	}

	return digest.MatchAdvanced(password)
}

// GetDetails retrieve the groups a user belongs to.
func (p *DatabaseUserProvider) GetDetails(username string) (details *UserDetails, err error) {
	var user *model.AuthenticationUser

	if user, err = p.load(username); err != nil {
		return nil, err
	}

	return databaseUserDetails(user), nil
}

// GetDetailsCached returns the details of a user. The database is always current, so it's the same as GetDetails.
func (p *DatabaseUserProvider) GetDetailsCached(username string) (details *UserDetails, err error) {
	return p.GetDetails(username)
}

// GetDetailsExtended retrieves the extended details of a user.
func (p *DatabaseUserProvider) GetDetailsExtended(username string) (details *UserDetailsExtended, err error) {
	var user *model.AuthenticationUser

	if user, err = p.load(username); err != nil {
		return nil, err
	}

	return &UserDetailsExtended{
		GivenName:   user.GivenName,
		FamilyName:  user.FamilyName,
		UserDetails: databaseUserDetails(user),
	}, nil
}

// GetDetailsExtendedCached returns the extended details of a user. The database is always current, so it's the same
// as GetDetailsExtended.
func (p *DatabaseUserProvider) GetDetailsExtendedCached(username string) (details *UserDetailsExtended, err error) {
	return p.GetDetailsExtended(username)
}

// UpdatePassword updates the password of the given user.
func (p *DatabaseUserProvider) UpdatePassword(username string, newPassword string) (err error) {
	var user *model.AuthenticationUser

	if user, err = p.load(username); err != nil {
		return err
	}

	return p.setPassword(user.Username, newPassword)
}

// ChangePassword validates the old password then changes the password of the given user.
func (p *DatabaseUserProvider) ChangePassword(username string, oldPassword string, newPassword string) (err error) {
	var user *model.AuthenticationUser

	if user, err = p.load(username); err != nil {
		return fmt.Errorf("%w : %v", ErrUserNotFound, err)
	}

	if strings.TrimSpace(newPassword) == "" || oldPassword == newPassword {
		return ErrPasswordWeak
	}

	var match bool

	if match, err = p.CheckUserPassword(user.Username, oldPassword); err != nil {
		return ErrAuthenticationFailed
	}

	if !match {
		return ErrIncorrectPassword
	}

	if err = p.setPassword(user.Username, newPassword); err != nil {
		return fmt.Errorf("%w : %v", ErrOperationFailed, err)
	}

	return nil
}

func (p *DatabaseUserProvider) setPassword(username, password string) (err error) {
	var digest algorithm.Digest

	if digest, err = p.hash.Hash(password); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), databaseUserProviderTimeout)
	defer cancel()

	return p.store.UpdateAuthenticationUserPassword(ctx, username, digest.Encode())
}

// load returns an enabled user by username, or by email when email searching is enabled. A user which does not exist,
// is disabled, or whose row has a signature which is not valid is reported as ErrUserNotFound.
func (p *DatabaseUserProvider) load(username string) (user *model.AuthenticationUser, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), databaseUserProviderTimeout)
	defer cancel()

	user, err = p.store.LoadAuthenticationUser(ctx, username)

	if errors.Is(err, ErrUserNotFound) && p.config.Search.Email && strings.Contains(username, "@") {
		user, err = p.store.LoadAuthenticationUserByEmail(ctx, username)
	}

	switch {
	case err == nil && user.Disabled:
		return nil, ErrUserNotFound
	case err == nil:
		return user, nil
	case errors.Is(err, ErrUserNotFound):
		return nil, ErrUserNotFound
	default:
		logging.Logger().WithError(err).WithField("username", username).Error("Error loading user from the database authentication backend")

		return nil, ErrUserNotFound
	}
}

func databaseUserDetails(user *model.AuthenticationUser) *UserDetails {
	return &UserDetails{
		Username:    user.Username,
		DisplayName: user.DisplayName,
		Emails:      []string{user.Email},
		Groups:      user.Groups,
	}
}
