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

	assert.True(t, all.Revokes("", at.Add(-time.Minute)), "a portal login before")
	assert.True(t, all.Revokes("app", at.Add(-time.Second)), "any client's login before")
	assert.False(t, all.Revokes("", at.Truncate(time.Second)), "a login in the same second is taken as after")
	assert.False(t, all.Revokes("", at.Add(time.Second)), "a login after")
	assert.False(t, all.Revokes("", time.Unix(0, 0).Add(-time.Hour).Add(time.Hour*500000)), "a login long after")
	assert.True(t, all.Revokes("", time.Unix(0, 0)), "an unknown login time")

	assert.True(t, app.Revokes("app", at.Add(-time.Minute)))
	assert.False(t, app.Revokes("other", at.Add(-time.Minute)), "another client")
	assert.False(t, app.Revokes("", at.Add(-time.Minute)), "the portal")
}
