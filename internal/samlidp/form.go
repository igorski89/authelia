// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package samlidp

import (
	"crypto/sha256"
	"encoding/base64"
	"html/template"
)

// responseFormScript submits the response form. It is the only script of the page, which the Content-Security-Policy
// allows by its hash, as for the form_post response mode of OpenID Connect 1.0.
const responseFormScript = "document.getElementById('SAMLResponseForm').submit();"

// responseFormTemplate posts the response to the assertion consumer service of the service provider, with a button for
// a browser which doesn't run the script.
var responseFormTemplate = template.Must(template.New("saml-response-form").Parse(`<!DOCTYPE html>` +
	`<html lang="en"><head><meta charset="utf-8"><title>Continue</title></head><body>` +
	`<form method="post" action="{{.URL}}" id="SAMLResponseForm">` +
	`<input type="hidden" name="SAMLResponse" value="{{.SAMLResponse}}">` +
	`<input type="hidden" name="RelayState" value="{{.RelayState}}">` +
	`<noscript><input type="submit" value="Continue"></noscript>` +
	`</form>` +
	`<script>` + responseFormScript + `</script>` +
	`</body></html>`))

// ContentSecurityPolicy is the Content-Security-Policy of the responses of the single sign-on endpoint, which allows the
// script of the response form and nothing else.
var ContentSecurityPolicy = func() string {
	sum := sha256.Sum256([]byte(responseFormScript))

	return "default-src 'none'; script-src 'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}()
