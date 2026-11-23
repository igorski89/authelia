// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package model

import (
	"database/sql"
	"time"
)

// AdministrationAuditEntry is one change made through the administration API or the users and groups commands.
type AdministrationAuditEntry struct {
	ID       int            `db:"id"`
	Time     time.Time      `db:"time"`
	Actor    string         `db:"actor"`
	Action   string         `db:"action"`
	Username sql.NullString `db:"username"`
	Group    sql.NullString `db:"group_name"`

	// Details is a JSON object describing the change, such as the names of the changed fields. It never carries a
	// password or password digest.
	Details sql.NullString `db:"details"`
}
