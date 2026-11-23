// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package storage

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/authelia/authelia/v4/internal/model"
)

const (
	authenticationUserSignatureContext      = "authelia:authentication_user:v1"
	authenticationUserGroupSignatureContext = "authelia:authentication_user_group:v1"
)

// CreateAuthenticationUser creates a user of the database authentication backend. The username and email are stored
// in their canonical form and the user is signed as it is saved. A username which is taken, or which belonged to a
// deleted user, is refused.
func (p *SQLProvider) CreateAuthenticationUser(ctx context.Context, user model.AuthenticationUser) (err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return err
	}

	user.Username = model.CanonicalAuthenticationUsername(user.Username)
	user.Email = model.CanonicalAuthenticationUsername(user.Email)

	if user.Username == "" || user.Email == "" {
		return fmt.Errorf("error creating authentication user: the username and email are required")
	}

	now := time.Now().UTC().Truncate(time.Second)

	user.CreatedAt, user.UpdatedAt = now, now
	user.Signature = p.authenticationUserSignature(&user)

	return p.inTransaction(ctx, func(ctx context.Context) (err error) {
		if err = p.checkAuthenticationUserAvailable(ctx, user.Username, user.Email, 0); err != nil {
			return fmt.Errorf("error creating authentication user '%s': %w", user.Username, err)
		}

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlInsertAuthenticationUser,
			user.CreatedAt, user.UpdatedAt, user.Username, user.Email, user.DisplayName, user.GivenName, user.FamilyName,
			user.Password, user.Disabled, user.Signature); err != nil {
			if IsUniqueViolation(err) {
				return fmt.Errorf("error creating authentication user '%s': %w", user.Username, ErrAuthenticationUsernameTaken)
			}

			return fmt.Errorf("error creating authentication user '%s': %w", user.Username, err)
		}

		// Checked again after the insert, in the same transaction, so a concurrent delete of the same username can't
		// slip between the check and the insert.
		if err = p.checkAuthenticationUsernameNotDeleted(ctx, user.Username); err != nil {
			return fmt.Errorf("error creating authentication user '%s': %w", user.Username, err)
		}

		return nil
	})
}

// LoadAuthenticationUser loads a user of the database authentication backend by username, with its groups. A user
// whose signature is not valid is refused with [ErrAuthenticationUserSignatureInvalid].
func (p *SQLProvider) LoadAuthenticationUser(ctx context.Context, username string) (user *model.AuthenticationUser, err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return nil, err
	}

	return p.loadAuthenticationUser(ctx, p.sqlSelectAuthenticationUserByUsername, model.CanonicalAuthenticationUsername(username))
}

// LoadAuthenticationUserByEmail loads a user of the database authentication backend by email, with its groups. A user
// whose signature is not valid is refused with [ErrAuthenticationUserSignatureInvalid].
func (p *SQLProvider) LoadAuthenticationUserByEmail(ctx context.Context, email string) (user *model.AuthenticationUser, err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return nil, err
	}

	return p.loadAuthenticationUser(ctx, p.sqlSelectAuthenticationUserByEmail, model.CanonicalAuthenticationUsername(email))
}

// LoadAuthenticationUsers loads a page of users of the database authentication backend ordered by username, with
// their groups. A user whose signature is not valid is left out and logged.
func (p *SQLProvider) LoadAuthenticationUsers(ctx context.Context, limit, page int) (users []model.AuthenticationUser, err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return nil, err
	}

	var rows []model.AuthenticationUser

	if err = p.conn(ctx).SelectContext(ctx, &rows, p.sqlSelectAuthenticationUsers, limit, limit*page); err != nil {
		return nil, fmt.Errorf("error selecting authentication users: %w", err)
	}

	users = make([]model.AuthenticationUser, 0, len(rows))

	for i := range rows {
		if !p.verifyAuthenticationUserSignature(&rows[i]) {
			p.log.WithField("username", rows[i].Username).Error("Authentication user has a signature which is not valid; it was not written by Authelia with the current key and is treated as if it does not exist")

			continue
		}

		if rows[i].Groups, err = p.loadAuthenticationUserGroupNames(ctx, &rows[i]); err != nil {
			return nil, err
		}

		users = append(users, rows[i])
	}

	return users, nil
}

// UpdateAuthenticationUserProfile updates the email and names of a user of the database authentication backend.
func (p *SQLProvider) UpdateAuthenticationUserProfile(ctx context.Context, username, email, displayName, givenName, familyName string) (err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return err
	}

	email = model.CanonicalAuthenticationUsername(email)

	if email == "" {
		return fmt.Errorf("error updating authentication user '%s': the email is required", username)
	}

	return p.updateAuthenticationUser(ctx, username, func(ctx context.Context, user *model.AuthenticationUser) (err error) {
		if email != user.Email {
			if err = p.checkAuthenticationUserAvailable(ctx, "", email, user.ID); err != nil {
				return err
			}
		}

		user.Email, user.DisplayName, user.GivenName, user.FamilyName = email, displayName, givenName, familyName

		return nil
	})
}

// UpdateAuthenticationUserPassword updates the password digest of a user of the database authentication backend. An
// empty digest removes the password.
func (p *SQLProvider) UpdateAuthenticationUserPassword(ctx context.Context, username, digest string) (err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return err
	}

	return p.updateAuthenticationUser(ctx, username, func(_ context.Context, user *model.AuthenticationUser) error {
		user.Password = sql.NullString{String: digest, Valid: digest != ""}

		return nil
	})
}

// UpdateAuthenticationUserDisabled disables or enables a user of the database authentication backend.
func (p *SQLProvider) UpdateAuthenticationUserDisabled(ctx context.Context, username string, disabled bool) (err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return err
	}

	return p.updateAuthenticationUser(ctx, username, func(_ context.Context, user *model.AuthenticationUser) error {
		user.Disabled = disabled

		return nil
	})
}

// DeleteAuthenticationUser deletes a user of the database authentication backend and its memberships, and records the
// username as deleted so it is never used again. Other data keyed by the username is not touched.
func (p *SQLProvider) DeleteAuthenticationUser(ctx context.Context, username string) (err error) {
	username = model.CanonicalAuthenticationUsername(username)

	return p.inTransaction(ctx, func(ctx context.Context) (err error) {
		var user model.AuthenticationUser

		if err = p.conn(ctx).GetContext(ctx, &user, p.sqlSelectAuthenticationUserByUsername, username); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("error deleting authentication user '%s': %w", username, ErrNoAuthenticationUser)
			}

			return fmt.Errorf("error selecting authentication user '%s': %w", username, err)
		}

		// Deleted explicitly as the SQLite connection does not enforce foreign keys.
		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlDeleteAuthenticationUserGroupsByUserID, user.ID); err != nil {
			return fmt.Errorf("error deleting the group memberships of authentication user '%s': %w", username, err)
		}

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlDeleteAuthenticationUser, user.ID); err != nil {
			return fmt.Errorf("error deleting authentication user '%s': %w", username, err)
		}

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlInsertAuthenticationUserDeleted, username, time.Now().UTC().Truncate(time.Second)); err != nil {
			return fmt.Errorf("error recording the deletion of authentication user '%s': %w", username, err)
		}

		return nil
	})
}

// CreateAuthenticationGroup creates a group of the database authentication backend.
func (p *SQLProvider) CreateAuthenticationGroup(ctx context.Context, name string) (err error) {
	if name == "" {
		return fmt.Errorf("error creating authentication group: the name is required")
	}

	if _, err = p.conn(ctx).ExecContext(ctx, p.sqlInsertAuthenticationGroup, time.Now().UTC().Truncate(time.Second), name); err != nil {
		if IsUniqueViolation(err) {
			return fmt.Errorf("error creating authentication group '%s': %w", name, ErrAuthenticationGroupExists)
		}

		return fmt.Errorf("error creating authentication group '%s': %w", name, err)
	}

	return nil
}

// LoadAuthenticationGroups loads every group of the database authentication backend ordered by name.
func (p *SQLProvider) LoadAuthenticationGroups(ctx context.Context) (groups []model.AuthenticationGroup, err error) {
	if err = p.conn(ctx).SelectContext(ctx, &groups, p.sqlSelectAuthenticationGroups); err != nil {
		return nil, fmt.Errorf("error selecting authentication groups: %w", err)
	}

	return groups, nil
}

// LoadAuthenticationGroupMembers loads the usernames of the members of a group of the database authentication backend
// ordered by username. A membership whose signature is not valid is left out and logged.
func (p *SQLProvider) LoadAuthenticationGroupMembers(ctx context.Context, name string) (usernames []string, err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return nil, err
	}

	var group *model.AuthenticationGroup

	if group, err = p.loadAuthenticationGroup(ctx, name); err != nil {
		return nil, err
	}

	var memberships []model.AuthenticationUserGroup

	if err = p.conn(ctx).SelectContext(ctx, &memberships, p.sqlSelectAuthenticationUserGroupsByGroupID, group.ID); err != nil {
		return nil, fmt.Errorf("error selecting the members of authentication group '%s': %w", name, err)
	}

	return p.verifiedAuthenticationUserGroups(memberships, func(m *model.AuthenticationUserGroup) string { return m.Username }), nil
}

// DeleteAuthenticationGroup deletes a group of the database authentication backend and its memberships.
func (p *SQLProvider) DeleteAuthenticationGroup(ctx context.Context, name string) (err error) {
	return p.inTransaction(ctx, func(ctx context.Context) (err error) {
		var group *model.AuthenticationGroup

		if group, err = p.loadAuthenticationGroup(ctx, name); err != nil {
			return err
		}

		// Deleted explicitly as the SQLite connection does not enforce foreign keys.
		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlDeleteAuthenticationUserGroupsByGroupID, group.ID); err != nil {
			return fmt.Errorf("error deleting the memberships of authentication group '%s': %w", name, err)
		}

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlDeleteAuthenticationGroup, group.ID); err != nil {
			return fmt.Errorf("error deleting authentication group '%s': %w", name, err)
		}

		return nil
	})
}

// AddAuthenticationUserGroup makes a user of the database authentication backend a member of a group. The membership
// is signed as it is saved.
func (p *SQLProvider) AddAuthenticationUserGroup(ctx context.Context, username, group string) (err error) {
	if err = p.ensureAuthenticationUserKey(ctx); err != nil {
		return err
	}

	return p.inTransaction(ctx, func(ctx context.Context) (err error) {
		var (
			user *model.AuthenticationUser
			g    *model.AuthenticationGroup
		)

		if user, err = p.LoadAuthenticationUser(ctx, username); err != nil {
			return err
		}

		if g, err = p.loadAuthenticationGroup(ctx, group); err != nil {
			return err
		}

		membership := model.AuthenticationUserGroup{UserID: user.ID, GroupID: g.ID, Username: user.Username, Group: g.Name}

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlInsertAuthenticationUserGroup,
			user.ID, g.ID, time.Now().UTC().Truncate(time.Second), p.authenticationUserGroupSignature(&membership)); err != nil {
			if IsUniqueViolation(err) {
				return fmt.Errorf("error adding authentication user '%s' to group '%s': %w", user.Username, g.Name, ErrAuthenticationUserGroupExists)
			}

			return fmt.Errorf("error adding authentication user '%s' to group '%s': %w", user.Username, g.Name, err)
		}

		return nil
	})
}

// RemoveAuthenticationUserGroup removes a user of the database authentication backend from a group.
func (p *SQLProvider) RemoveAuthenticationUserGroup(ctx context.Context, username, group string) (err error) {
	return p.inTransaction(ctx, func(ctx context.Context) (err error) {
		var (
			user model.AuthenticationUser
			g    *model.AuthenticationGroup
		)

		// The user signature is not verified: removing a membership never grants anything.
		if err = p.conn(ctx).GetContext(ctx, &user, p.sqlSelectAuthenticationUserByUsername, model.CanonicalAuthenticationUsername(username)); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return fmt.Errorf("error removing authentication user '%s' from group '%s': %w", username, group, ErrNoAuthenticationUser)
			}

			return fmt.Errorf("error selecting authentication user '%s': %w", username, err)
		}

		if g, err = p.loadAuthenticationGroup(ctx, group); err != nil {
			return err
		}

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlDeleteAuthenticationUserGroup, user.ID, g.ID); err != nil {
			return fmt.Errorf("error removing authentication user '%s' from group '%s': %w", user.Username, g.Name, err)
		}

		return nil
	})
}

func (p *SQLProvider) loadAuthenticationUser(ctx context.Context, query, value string) (user *model.AuthenticationUser, err error) {
	user = &model.AuthenticationUser{}

	if err = p.conn(ctx).GetContext(ctx, user, query, value); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrNoAuthenticationUser
		}

		return nil, fmt.Errorf("error selecting authentication user '%s': %w", value, err)
	}

	if !p.verifyAuthenticationUserSignature(user) {
		p.log.WithField("username", user.Username).Error("Authentication user has a signature which is not valid; it was not written by Authelia with the current key and is treated as if it does not exist")

		return nil, fmt.Errorf("error loading authentication user '%s': %w", user.Username, ErrAuthenticationUserSignatureInvalid)
	}

	if user.Groups, err = p.loadAuthenticationUserGroupNames(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (p *SQLProvider) loadAuthenticationUserGroupNames(ctx context.Context, user *model.AuthenticationUser) (groups []string, err error) {
	var memberships []model.AuthenticationUserGroup

	if err = p.conn(ctx).SelectContext(ctx, &memberships, p.sqlSelectAuthenticationUserGroupsByUserID, user.ID); err != nil {
		return nil, fmt.Errorf("error selecting the groups of authentication user '%s': %w", user.Username, err)
	}

	return p.verifiedAuthenticationUserGroups(memberships, func(m *model.AuthenticationUserGroup) string { return m.Group }), nil
}

func (p *SQLProvider) verifiedAuthenticationUserGroups(memberships []model.AuthenticationUserGroup, value func(m *model.AuthenticationUserGroup) string) (values []string) {
	values = make([]string, 0, len(memberships))

	for i := range memberships {
		if !p.verifyAuthenticationUserGroupSignature(&memberships[i]) {
			p.log.WithFields(map[string]any{"username": memberships[i].Username, "group": memberships[i].Group}).
				Error("Authentication group membership has a signature which is not valid; it was not written by Authelia with the current key and is treated as if it does not exist")

			continue
		}

		values = append(values, value(&memberships[i]))
	}

	return values
}

func (p *SQLProvider) loadAuthenticationGroup(ctx context.Context, name string) (group *model.AuthenticationGroup, err error) {
	group = &model.AuthenticationGroup{}

	if err = p.conn(ctx).GetContext(ctx, group, p.sqlSelectAuthenticationGroupByName, name); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("error loading authentication group '%s': %w", name, ErrNoAuthenticationGroup)
		}

		return nil, fmt.Errorf("error selecting authentication group '%s': %w", name, err)
	}

	return group, nil
}

// updateAuthenticationUser loads and verifies a user, applies the change, then signs and saves it, all in one
// transaction. Verifying first means a row changed outside Authelia is never signed again with the current key.
func (p *SQLProvider) updateAuthenticationUser(ctx context.Context, username string, change func(ctx context.Context, user *model.AuthenticationUser) error) (err error) {
	username = model.CanonicalAuthenticationUsername(username)

	return p.inTransaction(ctx, func(ctx context.Context) (err error) {
		var user *model.AuthenticationUser

		if user, err = p.loadAuthenticationUser(ctx, p.sqlSelectAuthenticationUserByUsername, username); err != nil {
			return fmt.Errorf("error updating authentication user '%s': %w", username, err)
		}

		if err = change(ctx, user); err != nil {
			return fmt.Errorf("error updating authentication user '%s': %w", username, err)
		}

		user.UpdatedAt = time.Now().UTC().Truncate(time.Second)
		user.Signature = p.authenticationUserSignature(user)

		if _, err = p.conn(ctx).ExecContext(ctx, p.sqlUpdateAuthenticationUser,
			user.UpdatedAt, user.Email, user.DisplayName, user.GivenName, user.FamilyName, user.Password, user.Disabled,
			user.Signature, user.ID); err != nil {
			if IsUniqueViolation(err) {
				return fmt.Errorf("error updating authentication user '%s': %w", username, ErrAuthenticationEmailTaken)
			}

			return fmt.Errorf("error updating authentication user '%s': %w", username, err)
		}

		return nil
	})
}

// checkAuthenticationUserAvailable checks that a username (when not empty) is neither taken nor deleted, and that an
// email is not used by a user other than the one with the given id. As users may log in with their email, a username
// must also not be the email of another user, and an email must not be the username of another user.
func (p *SQLProvider) checkAuthenticationUserAvailable(ctx context.Context, username, email string, id int) (err error) {
	if username != "" {
		if err = p.checkAuthenticationUserUnused(ctx, p.sqlSelectAuthenticationUserByUsername, username, id, ErrAuthenticationUsernameTaken); err != nil {
			return err
		}

		if err = p.checkAuthenticationUserUnused(ctx, p.sqlSelectAuthenticationUserByEmail, username, id, ErrAuthenticationUsernameTaken); err != nil {
			return err
		}

		if err = p.checkAuthenticationUsernameNotDeleted(ctx, username); err != nil {
			return err
		}
	}

	if err = p.checkAuthenticationUserUnused(ctx, p.sqlSelectAuthenticationUserByEmail, email, id, ErrAuthenticationEmailTaken); err != nil {
		return err
	}

	return p.checkAuthenticationUserUnused(ctx, p.sqlSelectAuthenticationUserByUsername, email, id, ErrAuthenticationEmailTaken)
}

// checkAuthenticationUserUnused returns errTaken when the query finds a user other than the one with the given id.
func (p *SQLProvider) checkAuthenticationUserUnused(ctx context.Context, query, value string, id int, errTaken error) (err error) {
	var user model.AuthenticationUser

	switch err = p.conn(ctx).GetContext(ctx, &user, query, value); {
	case err == nil:
		if id == 0 || user.ID != id {
			return errTaken
		}

		return nil
	case errors.Is(err, sql.ErrNoRows):
		return nil
	default:
		return err
	}
}

func (p *SQLProvider) checkAuthenticationUsernameNotDeleted(ctx context.Context, username string) (err error) {
	var count int

	if err = p.conn(ctx).GetContext(ctx, &count, p.sqlSelectAuthenticationUserDeletedCount, username); err != nil {
		return fmt.Errorf("error checking whether the username was deleted: %w", err)
	}

	if count != 0 {
		return ErrAuthenticationUsernameDeleted
	}

	return nil
}

// inTransaction runs fn in the transaction already carried by the context, or in a new one which is committed when fn
// succeeds and rolled back when it fails.
func (p *SQLProvider) inTransaction(ctx context.Context, fn func(ctx context.Context) error) (err error) {
	if tx, ok := ctx.Value(ctxKeyTransaction).(SQLXTx); ok && tx != nil {
		return fn(ctx)
	}

	if ctx, err = p.BeginTX(ctx); err != nil {
		return fmt.Errorf("error beginning transaction: %w", err)
	}

	if err = fn(ctx); err != nil {
		if rollbackErr := p.Rollback(ctx); rollbackErr != nil {
			return fmt.Errorf("error rolling back transaction: %w (after %w)", rollbackErr, err)
		}

		return err
	}

	if err = p.Commit(ctx); err != nil {
		return fmt.Errorf("error committing transaction: %w", err)
	}

	return nil
}

func authenticationUserSignature(key []byte, user *model.AuthenticationUser) string {
	password, disabled := "0", "0"

	if user.Password.Valid {
		password = "1"
	}

	if user.Disabled {
		disabled = "1"
	}

	return signatureHMACSHA512(key, authenticationUserSignatureContext, user.Username, user.Email, user.DisplayName,
		user.GivenName, user.FamilyName, password, user.Password.String, disabled)
}

func authenticationUserGroupSignature(key []byte, membership *model.AuthenticationUserGroup) string {
	return signatureHMACSHA512(key, authenticationUserGroupSignatureContext, membership.Username, membership.Group)
}

// signatureHMACSHA512 returns the hex encoded HMAC-SHA512 of the values, each prefixed by its length so that no two
// different lists of values have the same input.
func signatureHMACSHA512(key []byte, values ...string) string {
	h := hmac.New(sha512.New, key)

	var length [8]byte

	for _, value := range values {
		binary.BigEndian.PutUint64(length[:], uint64(len(value)))

		h.Write(length[:])
		h.Write([]byte(value))
	}

	return hex.EncodeToString(h.Sum(nil))
}

// LoadAuthenticationUserHMACKey loads the HMAC key of the database authentication backend into the storage provider,
// generating and persisting it when it does not exist. The startup check loads it; other callers which begin a
// transaction must load it first.
func (p *SQLProvider) LoadAuthenticationUserHMACKey(ctx context.Context) (err error) {
	return p.ensureAuthenticationUserKey(ctx)
}

// ensureAuthenticationUserKey loads the HMAC key when the provider has not loaded it yet, as the storage commands
// don't run the startup check. Signing or verifying with an empty key would make every row look tampered.
func (p *SQLProvider) ensureAuthenticationUserKey(ctx context.Context) (err error) {
	if len(p.keys.authenticationUserHMAC) != 0 {
		return nil
	}

	// Loading the key opens its own transaction, which would wait on the caller's transaction on SQLite.
	if tx, ok := ctx.Value(ctxKeyTransaction).(SQLXTx); ok && tx != nil {
		return fmt.Errorf("failed to initialize the hmac authentication user signature key: it must be loaded with LoadAuthenticationUserHMACKey before beginning a transaction")
	}

	var key []byte

	if key, err = p.getHMACAuthenticationUser(ctx); err != nil {
		return fmt.Errorf("failed to initialize the hmac authentication user signature key: %w", err)
	}

	if len(key) == 0 {
		return fmt.Errorf("failed to initialize the hmac authentication user signature key: the key is empty")
	}

	p.keys.authenticationUserHMAC = key

	return nil
}

func (p *SQLProvider) authenticationUserSignature(user *model.AuthenticationUser) string {
	return authenticationUserSignature(p.keys.authenticationUserHMAC, user)
}

func (p *SQLProvider) authenticationUserGroupSignature(membership *model.AuthenticationUserGroup) string {
	return authenticationUserGroupSignature(p.keys.authenticationUserHMAC, membership)
}

func (p *SQLProvider) verifyAuthenticationUserSignature(user *model.AuthenticationUser) bool {
	return verifyAuthenticationUserSignature(p.keys.authenticationUserHMAC, user)
}

func (p *SQLProvider) verifyAuthenticationUserGroupSignature(membership *model.AuthenticationUserGroup) bool {
	return verifyAuthenticationUserGroupSignature(p.keys.authenticationUserHMAC, membership)
}

func verifyAuthenticationUserSignature(key []byte, user *model.AuthenticationUser) bool {
	return len(key) != 0 && user.Signature != "" && hmac.Equal([]byte(authenticationUserSignature(key, user)), []byte(user.Signature))
}

func verifyAuthenticationUserGroupSignature(key []byte, membership *model.AuthenticationUserGroup) bool {
	return len(key) != 0 && membership.Signature != "" && hmac.Equal([]byte(authenticationUserGroupSignature(key, membership)), []byte(membership.Signature))
}

func (p *SQLProvider) getHMACAuthenticationUser(ctx context.Context) (key []byte, err error) {
	return p.getHMACKey(ctx, hmacNameAuthenticationUser, sha512.BlockSize)
}

// schemaEncryptionRotateHMACKeyAuthenticationUser generates a new HMAC key for the database authentication backend and
// signs every user and membership again with it. Unlike other rotations it never deletes anything: if any user or
// membership has a signature which is not valid for the current key the rotation is aborted, so an administrator can
// investigate the rows instead of losing users.
func (p *SQLProvider) schemaEncryptionRotateHMACKeyAuthenticationUser(ctx context.Context) (err error) {
	var tx SQLXTx

	if tx, err = p.db.Beginx(); err != nil {
		return fmt.Errorf("error beginning transaction to rotate hmac key: %w", err)
	}

	rollback := func(err error) error {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			return fmt.Errorf("error rolling back transaction to rotate hmac key: %w", rollbackErr)
		}

		return err
	}

	var current, key []byte

	if current, err = p.getEncryptionValue(ctx, tx, fmt.Sprintf(fmtNameKeyHMAC, hmacNameAuthenticationUser)); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return rollback(fmt.Errorf("error getting the current hmac key: %w", err))
	}

	var (
		users       []model.AuthenticationUser
		memberships []model.AuthenticationUserGroup
	)

	if err = tx.SelectContext(ctx, &users, p.db.Rebind(fmt.Sprintf(queryFmtSelectAuthenticationUsersAll, tableAuthenticationUsers))); err != nil {
		return rollback(fmt.Errorf("error selecting authentication users: %w", err))
	}

	if err = tx.SelectContext(ctx, &memberships, p.db.Rebind(fmt.Sprintf(queryFmtSelectAuthenticationUserGroupsAll, tableAuthenticationUserGroups, tableAuthenticationUsers, tableAuthenticationGroups))); err != nil {
		return rollback(fmt.Errorf("error selecting authentication group memberships: %w", err))
	}

	if err = verifyAuthenticationUsersForRotation(current, users, memberships); err != nil {
		return rollback(err)
	}

	if key, err = p.setCrypographyKey(ctx, tx, keyTypeCryptographyHMAC, hmacNameAuthenticationUser, sha512.BlockSize, true); err != nil {
		return rollback(fmt.Errorf("error setting the hmac key: %w", err))
	}

	if err = p.signAuthenticationUsersForRotation(ctx, tx, key, users, memberships); err != nil {
		return rollback(err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("error committing transaction to rotate hmac key: %w", err)
	}

	p.keys.authenticationUserHMAC = key

	p.log.Infof("Finished signing %d authentication user(s) and %d group membership(s) with the new hmac key", len(users), len(memberships))

	return nil
}

func verifyAuthenticationUsersForRotation(current []byte, users []model.AuthenticationUser, memberships []model.AuthenticationUserGroup) (err error) {
	for i := range users {
		if !verifyAuthenticationUserSignature(current, &users[i]) {
			return fmt.Errorf("error rotating hmac key: authentication user '%s' has a signature which is not valid for the current key: %w", users[i].Username, ErrAuthenticationUserSignatureInvalid)
		}
	}

	for i := range memberships {
		if !verifyAuthenticationUserGroupSignature(current, &memberships[i]) {
			return fmt.Errorf("error rotating hmac key: the membership of authentication user '%s' in group '%s' has a signature which is not valid for the current key: %w", memberships[i].Username, memberships[i].Group, ErrAuthenticationUserSignatureInvalid)
		}
	}

	return nil
}

func (p *SQLProvider) signAuthenticationUsersForRotation(ctx context.Context, tx SQLXTx, key []byte, users []model.AuthenticationUser, memberships []model.AuthenticationUserGroup) (err error) {
	queryUser := p.db.Rebind(fmt.Sprintf(queryFmtUpdateAuthenticationUserSignature, tableAuthenticationUsers))
	queryMembership := p.db.Rebind(fmt.Sprintf(queryFmtUpdateAuthenticationUserGroupSignature, tableAuthenticationUserGroups))

	for i := range users {
		if _, err = tx.ExecContext(ctx, queryUser, authenticationUserSignature(key, &users[i]), users[i].ID); err != nil {
			return fmt.Errorf("error signing authentication user '%s': %w", users[i].Username, err)
		}
	}

	for i := range memberships {
		if _, err = tx.ExecContext(ctx, queryMembership, authenticationUserGroupSignature(key, &memberships[i]), memberships[i].UserID, memberships[i].GroupID); err != nil {
			return fmt.Errorf("error signing the membership of authentication user '%s' in group '%s': %w", memberships[i].Username, memberships[i].Group, err)
		}
	}

	return nil
}
