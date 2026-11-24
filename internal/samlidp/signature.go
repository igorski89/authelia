// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package samlidp

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"io"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
)

const (
	// RequestSignatureIgnore is the request_signature of a service provider whose request signatures are ignored.
	RequestSignatureIgnore = "ignore"

	formFieldRedirectQuery = "SAMLRedirectQuery"
)

// IgnoresRequestSignature returns true if the signatures of the authentication requests of the service provider are
// ignored, and with them ForceAuthn, as Keycloak does when it doesn't require client signatures: the request can't be
// told from one anybody made.
func (sp *ServiceProvider) IgnoresRequestSignature() bool {
	return sp != nil && sp.Config.RequestSignature == RequestSignatureIgnore
}

// IgnoreRequestSignature removes the signature of an authentication request of a service provider whose request
// signatures are ignored, as the library verifies every signature which is present: the signature of the HTTP-Redirect
// binding from the query, or from the SAMLRedirectQuery field of an HTTP-POST, and the XML signature of the HTTP-POST
// binding. A request of any other service provider is left as it is. The form of an HTTP-POST must be parsed.
func (p *Provider) IgnoreRequestSignature(r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		if query, ok := p.stripRedirectQuery(r.URL.RawQuery); ok {
			r.URL.RawQuery = query
		}
	case http.MethodPost:
		if raw := r.PostForm.Get(formFieldRedirectQuery); raw != "" {
			if query, ok := p.stripRedirectQuery(raw); ok {
				r.PostForm.Set(formFieldRedirectQuery, query)
				r.Form.Set(formFieldRedirectQuery, query)
			}

			return
		}

		if encoded := r.PostForm.Get("SAMLRequest"); encoded != "" {
			if request, ok := p.stripPostRequest(encoded); ok {
				r.PostForm.Set("SAMLRequest", request)
				r.Form.Set("SAMLRequest", request)
			}
		}
	}
}

func (p *Provider) stripRedirectQuery(raw string) (query string, ok bool) {
	values, err := url.ParseQuery(raw)
	if err != nil || (!values.Has("Signature") && !values.Has("SigAlg")) {
		return "", false
	}

	encoded, err := base64.StdEncoding.DecodeString(values.Get("SAMLRequest"))
	if err != nil {
		return "", false
	}

	inflated, err := io.ReadAll(io.LimitReader(flate.NewReader(bytes.NewReader(encoded)), MaxBodyLength))
	if err != nil {
		return "", false
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(inflated); err != nil || !p.ignoresRequestSignatureOf(doc) {
		return "", false
	}

	values.Del("Signature")
	values.Del("SigAlg")

	return values.Encode(), true
}

func (p *Provider) stripPostRequest(encoded string) (request string, ok bool) {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(decoded); err != nil || !p.ignoresRequestSignatureOf(doc) {
		return "", false
	}

	root := doc.Root()

	signatures := root.SelectElements("Signature")
	if len(signatures) == 0 {
		return "", false
	}

	for _, signature := range signatures {
		root.RemoveChild(signature)
	}

	if decoded, err = doc.WriteToBytes(); err != nil {
		return "", false
	}

	return base64.StdEncoding.EncodeToString(decoded), true
}

// ignoresRequestSignatureOf returns true if the Issuer of the request is a service provider whose request signatures
// are ignored.
func (p *Provider) ignoresRequestSignatureOf(doc *etree.Document) bool {
	root := doc.Root()
	if root == nil {
		return false
	}

	issuer := root.SelectElement("Issuer")
	if issuer == nil {
		return false
	}

	return p.serviceProviders[issuer.Text()].IgnoresRequestSignature()
}
