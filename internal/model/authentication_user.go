// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"database/sql"
	"strings"
	"time"
)

// AuthenticationUser represents a user of the database authentication backend.
type AuthenticationUser struct {
	ID          int            `db:"id"`
	CreatedAt   time.Time      `db:"created_at"`
	UpdatedAt   time.Time      `db:"updated_at"`
	Username    string         `db:"username"`
	Email       string         `db:"email"`
	DisplayName string         `db:"display_name"`
	GivenName   string         `db:"given_name"`
	FamilyName  string         `db:"family_name"`
	Password    sql.NullString `db:"password"`
	Disabled    bool           `db:"disabled"`
	Signature   string         `db:"signature"`

	// Groups are the names of the groups the user is a member of, ordered by name. Only memberships with a valid
	// signature are included. They are never stored as part of the user.
	Groups []string `db:"-"`
}

// HasPassword returns true if the user has a password.
func (u *AuthenticationUser) HasPassword() bool {
	return u.Password.Valid && u.Password.String != ""
}

// AuthenticationGroup represents a group of the database authentication backend.
type AuthenticationGroup struct {
	ID        int       `db:"id"`
	CreatedAt time.Time `db:"created_at"`
	Name      string    `db:"name"`
}

// AuthenticationUserGroup represents the membership of a user in a group of the database authentication backend,
// joined with the username and the group name it is signed over.
type AuthenticationUserGroup struct {
	UserID    int       `db:"user_id"`
	GroupID   int       `db:"group_id"`
	CreatedAt time.Time `db:"created_at"`
	Username  string    `db:"username"`
	Group     string    `db:"name"`
	Signature string    `db:"signature"`
}

// CanonicalAuthenticationUsername returns the canonical form of a username or email of the database authentication
// backend. Every value is stored and looked up in this form, so the comparison is the same on every storage engine.
func CanonicalAuthenticationUsername(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}
