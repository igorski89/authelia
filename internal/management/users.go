// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

// Package management implements the management of the users and groups of the database authentication backend. The
// administration API and the CLI both use it, so the rules are the same whichever way a change is made.
package management

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"github.com/go-crypt/crypt/algorithm"

	"github.com/authelia/authelia/v4/internal/authentication"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/model"
	"github.com/authelia/authelia/v4/internal/storage"
)

const (
	// MaxUsernameLength is the longest username, as stored by the database authentication backend.
	MaxUsernameLength = 100

	// MaxEmailLength is the longest email.
	MaxEmailLength = 255

	// MaxDisplayNameLength is the longest display name.
	MaxDisplayNameLength = 255

	// MaxNameLength is the longest given name or family name.
	MaxNameLength = 100

	// MaxGroupLength is the longest group name.
	MaxGroupLength = 100

	// DefaultPageSize is the number of users listed when no page size is given.
	DefaultPageSize = 100

	// MaxPageSize is the largest number of users listed at once.
	MaxPageSize = 500
)

var (
	reUsername = regexp.MustCompile(`^[a-z0-9][a-z0-9._@-]*$`)
	reGroup    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
)

var (
	// ErrInvalid is wrapped by every error which reports input that breaks a rule.
	ErrInvalid = errors.New("invalid input")

	// ErrNotFound is wrapped by every error which reports a user or group which does not exist.
	ErrNotFound = errors.New("not found")

	// ErrConflict is wrapped by every error which reports a username, email, group, or membership which already exists,
	// or a username which belonged to a deleted user.
	ErrConflict = errors.New("conflict")
)

// PasswordPolicy checks a plain password before it is hashed.
type PasswordPolicy interface {
	Check(password string) (err error)
}

// Service manages the users and groups of the database authentication backend.
type Service struct {
	store  storage.Provider
	hash   algorithm.Hash
	policy PasswordPolicy
}

// New returns a new Service. The password policy is optional.
func New(config *schema.AuthenticationBackendDatabase, store storage.Provider, policy PasswordPolicy) (service *Service, err error) {
	if config == nil {
		return nil, fmt.Errorf("the database authentication backend is not configured")
	}

	if store == nil {
		return nil, fmt.Errorf("the database authentication backend requires the storage provider")
	}

	service = &Service{store: store, policy: policy}

	if service.hash, err = authentication.NewFileCryptoHashFromConfig(config.Password); err != nil {
		return nil, err
	}

	return service, nil
}

// User is a user of the database authentication backend as it is shown by the administration API and the CLI. It never
// carries the password digest.
type User struct {
	Username    string    `json:"username"`
	Email       string    `json:"email"`
	DisplayName string    `json:"display_name"`
	GivenName   string    `json:"given_name"`
	FamilyName  string    `json:"family_name"`
	Groups      []string  `json:"groups"`
	Disabled    bool      `json:"disabled"`
	HasPassword bool      `json:"has_password"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// Group is a group of the database authentication backend.
type Group struct {
	Name      string    `json:"name"`
	CreatedAt time.Time `json:"created_at"`
}

// Password is either a plain password, which is checked against the password policy and hashed, or a password digest
// in the PHC string format, which is stored as it is (for example when importing users from another system). At most
// one of them may be set.
type Password struct {
	Plain  string `json:"password,omitempty"`
	Digest string `json:"password_digest,omitempty"`
}

// NewUser is a user to create.
type NewUser struct {
	Username    string   `json:"username"`
	Email       string   `json:"email"`
	DisplayName string   `json:"display_name"`
	GivenName   string   `json:"given_name"`
	FamilyName  string   `json:"family_name"`
	Groups      []string `json:"groups"`
	Disabled    bool     `json:"disabled"`

	Password
}

// UserChanges are changes to a user. A nil value leaves the field as it is.
type UserChanges struct {
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	GivenName   *string `json:"given_name,omitempty"`
	FamilyName  *string `json:"family_name,omitempty"`
	Disabled    *bool   `json:"disabled,omitempty"`
}

// CreateUser creates a user and adds it to the given groups, which must exist, in one transaction.
func (s *Service) CreateUser(ctx context.Context, in NewUser) (user *User, err error) {
	username := model.CanonicalAuthenticationUsername(in.Username)

	if err = validateUsername(username); err != nil {
		return nil, err
	}

	row := model.AuthenticationUser{
		Username:    username,
		Email:       model.CanonicalAuthenticationUsername(in.Email),
		DisplayName: strings.TrimSpace(in.DisplayName),
		GivenName:   strings.TrimSpace(in.GivenName),
		FamilyName:  strings.TrimSpace(in.FamilyName),
		Disabled:    in.Disabled,
	}

	if err = validateProfile(row.Email, row.DisplayName, row.GivenName, row.FamilyName); err != nil {
		return nil, err
	}

	for _, group := range in.Groups {
		if err = validateGroup(group); err != nil {
			return nil, err
		}
	}

	if row.Password, err = s.digest(in.Password); err != nil {
		return nil, err
	}

	err = s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.CreateAuthenticationUser(ctx, row); err != nil {
			return err
		}

		for _, group := range in.Groups {
			if err = s.store.AddAuthenticationUserGroup(ctx, username, group); err != nil {
				return err
			}
		}

		return nil
	})
	if err != nil {
		return nil, wrap(err)
	}

	return s.GetUser(ctx, username)
}

// GetUser returns a user.
func (s *Service) GetUser(ctx context.Context, username string) (user *User, err error) {
	var row *model.AuthenticationUser

	if row, err = s.store.LoadAuthenticationUser(ctx, username); err != nil {
		return nil, wrap(err)
	}

	return newUser(row), nil
}

// ListUsers returns a page of users ordered by username. A zero limit lists DefaultPageSize users.
func (s *Service) ListUsers(ctx context.Context, limit, page int) (users []User, err error) {
	switch {
	case limit == 0:
		limit = DefaultPageSize
	case limit < 0 || limit > MaxPageSize:
		return nil, fmt.Errorf("%w: the limit must be between 1 and %d", ErrInvalid, MaxPageSize)
	}

	if page < 0 {
		return nil, fmt.Errorf("%w: the page must not be negative", ErrInvalid)
	}

	var rows []model.AuthenticationUser

	if rows, err = s.store.LoadAuthenticationUsers(ctx, limit, page); err != nil {
		return nil, wrap(err)
	}

	users = make([]User, len(rows))

	for i := range rows {
		users[i] = *newUser(&rows[i])
	}

	return users, nil
}

// UpdateUser changes the profile of a user, and disables or enables it.
func (s *Service) UpdateUser(ctx context.Context, username string, changes UserChanges) (user *User, err error) {
	var current *User

	if current, err = s.GetUser(ctx, username); err != nil {
		return nil, err
	}

	email, displayName, givenName, familyName := current.Email, current.DisplayName, current.GivenName, current.FamilyName

	if changes.Email != nil {
		email = model.CanonicalAuthenticationUsername(*changes.Email)
	}

	if changes.DisplayName != nil {
		displayName = strings.TrimSpace(*changes.DisplayName)
	}

	if changes.GivenName != nil {
		givenName = strings.TrimSpace(*changes.GivenName)
	}

	if changes.FamilyName != nil {
		familyName = strings.TrimSpace(*changes.FamilyName)
	}

	if err = validateProfile(email, displayName, givenName, familyName); err != nil {
		return nil, err
	}

	err = s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.UpdateAuthenticationUserProfile(ctx, current.Username, email, displayName, givenName, familyName); err != nil {
			return err
		}

		if changes.Disabled != nil && *changes.Disabled != current.Disabled {
			return s.store.UpdateAuthenticationUserDisabled(ctx, current.Username, *changes.Disabled)
		}

		return nil
	})
	if err != nil {
		return nil, wrap(err)
	}

	return s.GetUser(ctx, current.Username)
}

// SetPassword sets the password of a user. An empty Password removes it, so the user can only log in another way.
func (s *Service) SetPassword(ctx context.Context, username string, password Password) (err error) {
	var digest sql.NullString

	if digest, err = s.digest(password); err != nil {
		return err
	}

	return wrap(s.store.UpdateAuthenticationUserPassword(ctx, username, digest.String))
}

// DeleteUser deletes a user and the second factors and links which only make sense for it: passkeys and other
// WebAuthn credentials, the TOTP configuration, recovery codes, the preferred Duo device, and external identity links.
// The username is recorded so it is never used again; its subject identifiers are kept for the same reason. All of it
// happens in one transaction.
func (s *Service) DeleteUser(ctx context.Context, username string) (err error) {
	username = model.CanonicalAuthenticationUsername(username)

	return wrap(s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.DeleteAuthenticationUser(ctx, username); err != nil {
			return err
		}

		if err = s.store.DeleteWebAuthnCredentialByUsername(ctx, username, ""); err != nil {
			return err
		}

		if err = s.store.DeleteTOTPConfiguration(ctx, username); err != nil {
			return err
		}

		if err = s.store.RevokeRecoveryCodesByUsername(ctx, username, model.NullIP{}); err != nil {
			return err
		}

		if err = s.store.DeletePreferredDuoDevice(ctx, username); err != nil {
			return err
		}

		var links []model.ExternalIdentityLink

		if links, err = s.store.LoadExternalIdentityLinksByUsername(ctx, username); err != nil {
			return err
		}

		for _, link := range links {
			if err = s.store.DeleteExternalIdentityLink(ctx, username, link.ID); err != nil {
				return err
			}
		}

		return nil
	}))
}

// AddUserToGroup makes a user a member of a group.
func (s *Service) AddUserToGroup(ctx context.Context, username, group string) (err error) {
	return wrap(s.store.AddAuthenticationUserGroup(ctx, username, group))
}

// RemoveUserFromGroup removes a user from a group.
func (s *Service) RemoveUserFromGroup(ctx context.Context, username, group string) (err error) {
	return wrap(s.store.RemoveAuthenticationUserGroup(ctx, username, group))
}

// CreateGroup creates a group.
func (s *Service) CreateGroup(ctx context.Context, name string) (err error) {
	if err = validateGroup(name); err != nil {
		return err
	}

	return wrap(s.store.CreateAuthenticationGroup(ctx, name))
}

// ListGroups returns every group ordered by name.
func (s *Service) ListGroups(ctx context.Context) (groups []Group, err error) {
	var rows []model.AuthenticationGroup

	if rows, err = s.store.LoadAuthenticationGroups(ctx); err != nil {
		return nil, wrap(err)
	}

	groups = make([]Group, len(rows))

	for i, row := range rows {
		groups[i] = Group{Name: row.Name, CreatedAt: row.CreatedAt}
	}

	return groups, nil
}

// GroupMembers returns the usernames of the members of a group ordered by username.
func (s *Service) GroupMembers(ctx context.Context, name string) (usernames []string, err error) {
	if usernames, err = s.store.LoadAuthenticationGroupMembers(ctx, name); err != nil {
		return nil, wrap(err)
	}

	return usernames, nil
}

// DeleteGroup deletes a group and its memberships.
func (s *Service) DeleteGroup(ctx context.Context, name string) (err error) {
	return wrap(s.store.DeleteAuthenticationGroup(ctx, name))
}

// transaction runs fn in one storage transaction. The signing key is loaded first, as it can't be loaded inside one.
func (s *Service) transaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if err = s.store.LoadAuthenticationUserHMACKey(ctx); err != nil {
		return err
	}

	var txctx context.Context

	if txctx, err = s.store.BeginTX(ctx); err != nil {
		return fmt.Errorf("error beginning transaction: %w", err)
	}

	if err = fn(txctx); err != nil {
		if rollbackErr := s.store.Rollback(txctx); rollbackErr != nil {
			return fmt.Errorf("error rolling back transaction: %w (after %w)", rollbackErr, err)
		}

		return err
	}

	if err = s.store.Commit(txctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

func (s *Service) digest(password Password) (digest sql.NullString, err error) {
	switch {
	case password.Plain != "" && password.Digest != "":
		return digest, fmt.Errorf("%w: only one of the password and the password digest may be given", ErrInvalid)
	case password.Plain != "":
		if s.policy != nil {
			if err = s.policy.Check(password.Plain); err != nil {
				return digest, fmt.Errorf("%w: the password does not meet the password policy: %w", ErrInvalid, err)
			}
		}

		var d algorithm.Digest

		if d, err = s.hash.Hash(password.Plain); err != nil {
			return digest, fmt.Errorf("error hashing the password: %w", err)
		}

		return sql.NullString{String: d.Encode(), Valid: true}, nil
	case password.Digest != "":
		if _, err = schema.DecodePasswordDigest(password.Digest); err != nil {
			return digest, fmt.Errorf("%w: the password digest is not a supported PHC string: %w", ErrInvalid, err)
		}

		return sql.NullString{String: password.Digest, Valid: true}, nil
	default:
		return digest, nil
	}
}

func newUser(row *model.AuthenticationUser) *User {
	groups := row.Groups
	if groups == nil {
		groups = []string{}
	}

	return &User{
		Username:    row.Username,
		Email:       row.Email,
		DisplayName: row.DisplayName,
		GivenName:   row.GivenName,
		FamilyName:  row.FamilyName,
		Groups:      groups,
		Disabled:    row.Disabled,
		HasPassword: row.HasPassword(),
		CreatedAt:   row.CreatedAt,
		UpdatedAt:   row.UpdatedAt,
	}
}

func validateUsername(username string) error {
	switch {
	case username == "":
		return fmt.Errorf("%w: the username is required", ErrInvalid)
	case len(username) > MaxUsernameLength:
		return fmt.Errorf("%w: the username must not be longer than %d characters", ErrInvalid, MaxUsernameLength)
	case !reUsername.MatchString(username):
		return fmt.Errorf("%w: the username must start with a letter or digit and only contain lowercase letters, digits, '.', '_', '@', and '-'", ErrInvalid)
	}

	return nil
}

func validateProfile(email, displayName, givenName, familyName string) error {
	if email == "" {
		return fmt.Errorf("%w: the email is required", ErrInvalid)
	}

	if len(email) > MaxEmailLength {
		return fmt.Errorf("%w: the email must not be longer than %d characters", ErrInvalid, MaxEmailLength)
	}

	if address, err := mail.ParseAddress(email); err != nil || address.Address != email || address.Name != "" {
		return fmt.Errorf("%w: the email '%s' is not a valid address", ErrInvalid, email)
	}

	if len(displayName) > MaxDisplayNameLength {
		return fmt.Errorf("%w: the display name must not be longer than %d characters", ErrInvalid, MaxDisplayNameLength)
	}

	if len(givenName) > MaxNameLength || len(familyName) > MaxNameLength {
		return fmt.Errorf("%w: the given name and family name must not be longer than %d characters", ErrInvalid, MaxNameLength)
	}

	return nil
}

func validateGroup(name string) error {
	switch {
	case name == "":
		return fmt.Errorf("%w: the group name is required", ErrInvalid)
	case len(name) > MaxGroupLength:
		return fmt.Errorf("%w: the group name must not be longer than %d characters", ErrInvalid, MaxGroupLength)
	case !reGroup.MatchString(name):
		return fmt.Errorf("%w: the group name must start with a letter or digit and only contain letters, digits, '.', '_', and '-'", ErrInvalid)
	}

	return nil
}

// wrap maps storage errors onto ErrNotFound and ErrConflict, so the API and the CLI can report them without knowing
// the storage errors.
func wrap(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, authentication.ErrUserNotFound), errors.Is(err, storage.ErrNoAuthenticationGroup):
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case errors.Is(err, storage.ErrAuthenticationUsernameTaken), errors.Is(err, storage.ErrAuthenticationUsernameDeleted),
		errors.Is(err, storage.ErrAuthenticationEmailTaken), errors.Is(err, storage.ErrAuthenticationGroupExists),
		errors.Is(err, storage.ErrAuthenticationUserGroupExists):
		return fmt.Errorf("%w: %w", ErrConflict, err)
	default:
		return err
	}
}
