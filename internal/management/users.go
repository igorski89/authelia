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

// Sessions counts and destroys the portal sessions of a user. The server's session provider implements it; the CLI
// has none when sessions are kept in the memory of the running server.
type Sessions interface {
	CountByUsername(ctx context.Context, username string) (count int, err error)
	DestroyByUsername(ctx context.Context, username string) (destroyed int, err error)
}

// PasswordPolicy checks a plain password before it is hashed.
type PasswordPolicy interface {
	Check(password string) (err error)
}

// Service manages the users and groups of the database authentication backend.
type Service struct {
	store    storage.Provider
	sessions Sessions
	hash     algorithm.Hash
	policy   PasswordPolicy
}

// New returns a new Service. The password policy and the sessions are optional; without the sessions, revoking a
// user leaves its portal sessions, which are still refused once the user is disabled or deleted.
func New(config *schema.AuthenticationBackendDatabase, store storage.Provider, policy PasswordPolicy, sessions Sessions) (service *Service, err error) {
	if config == nil {
		return nil, fmt.Errorf("the database authentication backend is not configured")
	}

	if store == nil {
		return nil, fmt.Errorf("the database authentication backend requires the storage provider")
	}

	service = &Service{store: store, policy: policy, sessions: sessions}

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

	// Credentials are the kinds of credentials the user has: password, webauthn (passkeys and security keys), totp,
	// and duo. Only GetUser fills them.
	Credentials []string `json:"credentials,omitempty"`

	// Sessions is the number of portal sessions of the user. Only GetUser fills it, and only when the sessions can be
	// reached.
	Sessions *int `json:"sessions,omitempty"`
}

// Revocation reports what revoking a user did.
type Revocation struct {
	// Sessions is the number of portal sessions destroyed, or nil when the sessions can't be reached from here.
	Sessions *int `json:"sessions"`

	// Tokens is the number of OAuth 2.0 and OpenID Connect 1.0 sessions and pre-configured consents revoked.
	Tokens int64 `json:"tokens"`

	// Links is the number of pending links and one-time codes sent by email (such as invites) revoked.
	Links int64 `json:"links"`
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

		return s.audit(ctx, AuditActionUserCreate, username, "", map[string]any{"groups": in.Groups, "disabled": in.Disabled, "password": passwordKind(in.Password)})
	})
	if err != nil {
		return nil, wrap(err)
	}

	return s.getUser(ctx, username)
}

// GetUser returns a user with its kinds of credentials and, when the sessions can be reached, its number of portal
// sessions.
func (s *Service) GetUser(ctx context.Context, username string) (user *User, err error) {
	if user, err = s.getUser(ctx, username); err != nil {
		return nil, err
	}

	var info model.UserInfo

	if info, err = s.store.LoadUserInfo(ctx, user.Username); err != nil {
		return nil, err
	}

	user.Credentials = []string{}

	for _, credential := range []struct {
		name string
		has  bool
	}{{"password", user.HasPassword}, {"webauthn", info.HasWebAuthn}, {"totp", info.HasTOTP}, {"duo", info.HasDuo}} {
		if credential.has {
			user.Credentials = append(user.Credentials, credential.name)
		}
	}

	if s.sessions != nil {
		var count int

		if count, err = s.sessions.CountByUsername(ctx, user.Username); err != nil {
			return nil, err
		}

		user.Sessions = &count
	}

	return user, nil
}

func (s *Service) getUser(ctx context.Context, username string) (user *User, err error) {
	var row *model.AuthenticationUser

	if row, err = s.store.LoadAuthenticationUser(ctx, username); err != nil {
		return nil, wrap(err)
	}

	return newUser(row), nil
}

// RevokeUser ends everything the user is logged in with: its portal sessions (when they can be reached) and its
// OAuth 2.0 and OpenID Connect 1.0 tokens and pre-configured consent. When the client identifier isn't empty only the
// tokens of that client are revoked and the portal sessions are kept. JWT access tokens which an app validates itself
// stay valid until they expire. The user may be disabled or deleted, so it is not looked up.
func (s *Service) RevokeUser(ctx context.Context, username, clientID string) (revocation *Revocation, err error) {
	username = model.CanonicalAuthenticationUsername(username)

	if err = validateUsername(username); err != nil {
		return nil, err
	}

	revocation = &Revocation{}

	err = s.transaction(ctx, func(ctx context.Context) (err error) {
		if revocation.Tokens, err = s.store.RevokeOAuth2SessionsByUsername(ctx, username, clientID); err != nil {
			return err
		}

		details := map[string]any{"tokens": revocation.Tokens}

		// A full logout also revokes pending links and codes sent by email, such as an invite, so none outlives it.
		if clientID == "" {
			if revocation.Links, err = s.store.RevokeIdentityVerificationsByUsername(ctx, username, ""); err != nil {
				return err
			}

			details["links"] = revocation.Links
		}

		if clientID != "" {
			details["client_id"] = clientID
		}

		return s.audit(ctx, AuditActionUserLogout, username, "", details)
	})
	if err != nil {
		return nil, err
	}

	if s.sessions != nil && clientID == "" {
		var destroyed int

		if destroyed, err = s.sessions.DestroyByUsername(ctx, username); err != nil {
			return revocation, err
		}

		revocation.Sessions = &destroyed
	}

	return revocation, nil
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

// UpdateUser changes the profile of a user, and disables or enables it. The user is read and changed in one
// transaction, so concurrent updates of different fields don't undo each other.
func (s *Service) UpdateUser(ctx context.Context, username string, changes UserChanges) (user *User, err error) {
	var canonical string

	err = s.transaction(ctx, func(ctx context.Context) (err error) {
		var current *model.AuthenticationUser

		if current, err = s.store.LoadAuthenticationUser(ctx, username); err != nil {
			return err
		}

		canonical = current.Username

		if err = s.updateProfile(ctx, current, changes); err != nil {
			return err
		}

		return s.updateDisabled(ctx, current, changes.Disabled)
	})
	if err != nil {
		return nil, wrap(err)
	}

	// Disabling a user ends everything it is logged in with. It runs after the user is disabled, so nothing new can be
	// issued in between.
	if changes.Disabled != nil && *changes.Disabled {
		if _, err = s.RevokeUser(ctx, canonical, ""); err != nil {
			return nil, fmt.Errorf("the user was disabled but revoking its sessions and tokens failed: %w", err)
		}
	}

	return s.getUser(ctx, canonical)
}

// updateProfile applies the profile changes which differ from the current values, and audits the changed fields.
func (s *Service) updateProfile(ctx context.Context, current *model.AuthenticationUser, changes UserChanges) (err error) {
	fields := []struct {
		name    string
		current string
		change  *string
		value   string
	}{
		{"email", current.Email, changes.Email, ""},
		{"display_name", current.DisplayName, changes.DisplayName, ""},
		{"given_name", current.GivenName, changes.GivenName, ""},
		{"family_name", current.FamilyName, changes.FamilyName, ""},
	}

	var changed []string

	for i := range fields {
		fields[i].value = fields[i].current

		if fields[i].change != nil {
			fields[i].value = strings.TrimSpace(*fields[i].change)
		}

		if i == 0 {
			fields[i].value = model.CanonicalAuthenticationUsername(fields[i].value)
		}

		if fields[i].value != fields[i].current {
			changed = append(changed, fields[i].name)
		}
	}

	email, displayName, givenName, familyName := fields[0].value, fields[1].value, fields[2].value, fields[3].value

	if err = validateProfile(email, displayName, givenName, familyName); err != nil {
		return err
	}

	if len(changed) == 0 {
		return nil
	}

	if err = s.store.UpdateAuthenticationUserProfile(ctx, current.Username, email, displayName, givenName, familyName); err != nil {
		return err
	}

	return s.audit(ctx, AuditActionUserUpdate, current.Username, "", map[string]any{"fields": changed})
}

// updateDisabled disables or enables the user when that changes it, and audits it.
func (s *Service) updateDisabled(ctx context.Context, current *model.AuthenticationUser, disabled *bool) (err error) {
	if disabled == nil || *disabled == current.Disabled {
		return nil
	}

	if err = s.store.UpdateAuthenticationUserDisabled(ctx, current.Username, *disabled); err != nil {
		return err
	}

	if *disabled {
		return s.audit(ctx, AuditActionUserDisable, current.Username, "", nil)
	}

	return s.audit(ctx, AuditActionUserEnable, current.Username, "", nil)
}

// SetPassword sets the password of a user. An empty Password removes it, so the user can only log in another way.
func (s *Service) SetPassword(ctx context.Context, username string, password Password) (err error) {
	var digest sql.NullString

	if digest, err = s.digest(password); err != nil {
		return err
	}

	username = model.CanonicalAuthenticationUsername(username)

	return wrap(s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.UpdateAuthenticationUserPassword(ctx, username, digest.String); err != nil {
			return err
		}

		if !digest.Valid {
			return s.audit(ctx, AuditActionUserPasswordRemove, username, "", nil)
		}

		return s.audit(ctx, AuditActionUserPasswordSet, username, "", map[string]any{"password": passwordKind(password)})
	}))
}

// DeleteUser deletes a user, ends everything it is logged in with (see RevokeUser), and deletes the second factors and
// links which only make sense for it: passkeys and other
// WebAuthn credentials, the TOTP configuration, recovery codes, the preferred Duo device, and external identity links.
// The username is recorded so it is never used again; its subject identifiers are kept for the same reason. All of it
// happens in one transaction.
func (s *Service) DeleteUser(ctx context.Context, username string) (err error) {
	username = model.CanonicalAuthenticationUsername(username)

	if err = s.deleteUser(ctx, username); err != nil {
		return err
	}

	if _, err = s.RevokeUser(ctx, username, ""); err != nil {
		return fmt.Errorf("the user was deleted but revoking its sessions and tokens failed: %w", err)
	}

	return nil
}

func (s *Service) deleteUser(ctx context.Context, username string) (err error) {
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

		return s.audit(ctx, AuditActionUserDelete, username, "", nil)
	}))
}

// AddUserToGroup makes a user a member of a group.
func (s *Service) AddUserToGroup(ctx context.Context, username, group string) (err error) {
	username = model.CanonicalAuthenticationUsername(username)

	return wrap(s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.AddAuthenticationUserGroup(ctx, username, group); err != nil {
			return err
		}

		return s.audit(ctx, AuditActionGroupMemberAdd, username, group, nil)
	}))
}

// RemoveUserFromGroup removes a user from a group.
func (s *Service) RemoveUserFromGroup(ctx context.Context, username, group string) (err error) {
	username = model.CanonicalAuthenticationUsername(username)

	return wrap(s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.RemoveAuthenticationUserGroup(ctx, username, group); err != nil {
			return err
		}

		return s.audit(ctx, AuditActionGroupMemberRemove, username, group, nil)
	}))
}

// CreateGroup creates a group.
func (s *Service) CreateGroup(ctx context.Context, name string) (err error) {
	if err = validateGroup(name); err != nil {
		return err
	}

	return wrap(s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.CreateAuthenticationGroup(ctx, name); err != nil {
			return err
		}

		return s.audit(ctx, AuditActionGroupCreate, "", name, nil)
	}))
}

// ListGroups returns every group ordered by name.
func (s *Service) ListGroups(ctx context.Context) (groups []Group, err error) {
	var rows []model.AuthenticationGroup

	if rows, err = s.store.LoadAuthenticationGroups(ctx); err != nil {
		return nil, wrap(err)
	}

	groups = make([]Group, len(rows))

	for i, row := range rows {
		groups[i] = Group{Name: row.Name, CreatedAt: row.CreatedAt.UTC()}
	}

	return groups, nil
}

// GroupMembers returns the members of a group ordered by username.
func (s *Service) GroupMembers(ctx context.Context, name string) (members []User, err error) {
	var usernames []string

	if usernames, err = s.store.LoadAuthenticationGroupMembers(ctx, name); err != nil {
		return nil, wrap(err)
	}

	members = make([]User, 0, len(usernames))

	for _, username := range usernames {
		var user *User

		switch user, err = s.getUser(ctx, username); {
		case errors.Is(err, ErrNotFound):
			// A member whose row is not valid is left out, as it is everywhere else.
			continue
		case err != nil:
			return nil, err
		}

		members = append(members, *user)
	}

	return members, nil
}

// DeleteGroup deletes a group and its memberships.
func (s *Service) DeleteGroup(ctx context.Context, name string) (err error) {
	return wrap(s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.store.DeleteAuthenticationGroup(ctx, name); err != nil {
			return err
		}

		return s.audit(ctx, AuditActionGroupDelete, "", name, nil)
	}))
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

func passwordKind(password Password) string {
	switch {
	case password.Plain != "":
		return "plain"
	case password.Digest != "":
		return "digest"
	default:
		return "none"
	}
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

		// The plaintext and base64 schemes would store the password itself and skip the password policy.
		for _, prefix := range []string{"$plaintext$", "$base64$"} {
			if strings.HasPrefix(password.Digest, prefix) {
				return digest, fmt.Errorf("%w: the password digest must be a hash such as argon2id, scrypt, pbkdf2, bcrypt, or sha2crypt, not a stored password", ErrInvalid)
			}
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
		CreatedAt:   row.CreatedAt.UTC(),
		UpdatedAt:   row.UpdatedAt.UTC(),
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
