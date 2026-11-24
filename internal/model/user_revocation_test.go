// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestUserRevocationRevokes(t *testing.T) {
	at := time.Date(2026, 11, 24, 12, 0, 0, 600_000_000, time.UTC)

	all := UserRevocation{Username: "john", RevokedAt: at}
	app := UserRevocation{Username: "john", ClientID: "app", RevokedAt: at}

	// Portal logins, whose time has a resolution of a second.
	assert.True(t, all.Revokes("", at.Add(-time.Minute), time.Second), "a portal login before")
	assert.False(t, all.Revokes("", at.Truncate(time.Second), time.Second), "a login in the same second is taken as after")
	assert.False(t, all.Revokes("", at.Add(time.Second), time.Second), "a login after")
	assert.True(t, all.Revokes("", time.Unix(0, 0), time.Second), "an unknown login time")

	// Authorization requests, whose time is exact.
	assert.True(t, all.Revokes("app", at.Add(-time.Millisecond), 0), "a grant requested just before, in the same second")
	assert.False(t, all.Revokes("app", at.Add(time.Millisecond), 0), "a grant requested just after")

	assert.True(t, app.Revokes("app", at.Add(-time.Minute), 0))
	assert.False(t, app.Revokes("other", at.Add(-time.Minute), 0), "another client")
	assert.False(t, app.Revokes("", at.Add(-time.Minute), time.Second), "the portal")
}
