// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/model"
)

const (
	// ActionAccountSetup is the identity verification action of invite links.
	ActionAccountSetup = "AccountSetup"

	// DefaultInviteLifespan is how long an invite link is valid when no lifespan is given.
	DefaultInviteLifespan = 72 * time.Hour

	// MaxInviteLifespan is the longest an invite link can be valid.
	MaxInviteLifespan = 30 * 24 * time.Hour

	// AuditActionUserInvite is the audit action of creating an invite.
	AuditActionUserInvite = "user.invite"

	// AuditActionUserSetup is the audit action of an invited user setting up their account.
	AuditActionUserSetup = "user.setup"
)

// Invite is an invite link which was created for a user and still has to be sent.
type Invite struct {
	User         *User
	Verification model.IdentityVerification
}

// CreateInvite creates a one-time invite link for an enabled user, valid for the lifespan (DefaultInviteLifespan when
// zero, at most MaxInviteLifespan), and revokes the earlier invite links of the user. Redeeming it lets the user set a
// password and register a passkey, so inviting an existing user resets its credentials; the audit records it. The
// caller signs and sends the link, and revokes it with RevokeInvite when sending fails. The IP is that of the request
// which created the invite.
func (s *Service) CreateInvite(ctx context.Context, username string, lifespan time.Duration, ip net.IP) (invite *Invite, err error) {
	switch {
	case lifespan == 0:
		lifespan = DefaultInviteLifespan
	case lifespan < time.Second || lifespan > MaxInviteLifespan:
		return nil, fmt.Errorf("%w: the lifespan must be between 1 second and %s", ErrInvalid, MaxInviteLifespan)
	}

	var user *User

	if user, err = s.getUser(ctx, username); err != nil {
		return nil, err
	}

	if user.Disabled {
		return nil, fmt.Errorf("%w: the user is disabled; enable it before inviting it", ErrInvalid)
	}

	var jti uuid.UUID

	if jti, err = uuid.NewRandom(); err != nil {
		return nil, fmt.Errorf("error generating the invite identifier: %w", err)
	}

	invite = &Invite{User: user, Verification: model.NewIdentityVerification(jti, user.Username, ActionAccountSetup, ip, lifespan)}

	err = s.transaction(ctx, func(ctx context.Context) (err error) {
		if _, err = s.store.RevokePendingIdentityVerificationsByUsername(ctx, user.Username, ActionAccountSetup); err != nil {
			return err
		}

		if err = s.store.SaveIdentityVerification(ctx, invite.Verification); err != nil {
			return err
		}

		return s.audit(ctx, AuditActionUserInvite, user.Username, "", map[string]any{"expires_at": invite.Verification.ExpiresAt.UTC()})
	})
	if err != nil {
		return nil, wrap(err)
	}

	return invite, nil
}

// RevokeInvite revokes an invite link which could not be sent.
func (s *Service) RevokeInvite(ctx context.Context, invite *Invite) (err error) {
	return s.store.RevokeIdentityVerification(ctx, invite.Verification.JTI.String(), model.NullIP{})
}

// AuditAccountSetup records that an invited user set up their account; the user is the actor.
func (s *Service) AuditAccountSetup(ctx context.Context, username string) (err error) {
	return s.audit(WithActor(ctx, "user:"+username), AuditActionUserSetup, username, "", nil)
}
