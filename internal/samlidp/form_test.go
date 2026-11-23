// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package samlidp

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestResponseFormScriptHash checks that every script of the response page is allowed by the Content-Security-Policy,
// so a change to the template can't break the automatic submission unnoticed.
func TestResponseFormScriptHash(t *testing.T) {
	buf := &bytes.Buffer{}

	require.NoError(t, responseFormTemplate.Execute(buf, map[string]string{"URL": "https://sp.example.com/acs", "SAMLResponse": "x", "RelayState": "<y>"}))

	scripts := regexp.MustCompile(`<script>(.*?)</script>`).FindAllStringSubmatch(buf.String(), -1)
	require.Len(t, scripts, 1)

	sum := sha256.Sum256([]byte(scripts[0][1]))

	assert.Equal(t, "default-src 'none'; script-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'", ContentSecurityPolicy)
	assert.Contains(t, buf.String(), `value="&lt;y&gt;"`)
}
