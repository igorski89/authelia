// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

package validator

import (
	"fmt"
	"strings"
	"unicode"

	"github.com/authelia/authelia/v4/internal/configuration/schema"
)

// SGNL fork: the server path may have several segments (e.g. '/realms/example-realm'), so an existing issuer that
// lives under such a path can be kept. Upstream allows a single alphanumeric segment only. Each segment must be
// non-empty and contain only letters and digits (as upstream: [unicode.IsLetter], [unicode.IsNumber]), '-' and '_'.
// This keeps the path free of characters that are special in URLs or in the regular expression that
// middlewares.StripPath builds from it.
const (
	errFmtSGNLServerPathEmptySegment = "server: option 'address' must not have empty path segments or a trailing " +
		"slash but it's configured as '%s'"
	errFmtSGNLServerPathCharacters = "server: option 'address' must have a path with only alphanumeric characters, " +
		"'-' and '_' in each segment but it's configured as '%s'"
)

// Upstream's messages for the single-segment rule are no longer used. They are referenced here instead of being
// deleted from const.go, so that const.go (changed often upstream) stays untouched.
var (
	_ = errFmtServerPathNotEndForwardSlash
	_ = errFmtServerPathAlphaNumeric
)

func sgnlValidateServerPath(subpath string, validator *schema.StructValidator) {
	for _, segment := range strings.Split(strings.TrimPrefix(subpath, "/"), "/") {
		if segment == "" {
			validator.Push(fmt.Errorf(errFmtSGNLServerPathEmptySegment, subpath))

			return
		}

		for _, r := range segment {
			if !sgnlIsServerPathRune(r) {
				validator.Push(fmt.Errorf(errFmtSGNLServerPathCharacters, subpath))

				return
			}
		}
	}
}

func sgnlIsServerPathRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || r == '-' || r == '_'
}
