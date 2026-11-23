// SPDX-FileCopyrightText: 2026 SGNL fork contributors
//
// SPDX-License-Identifier: Apache-2.0

// Command samlsp is a SAML 2.0 service provider for the end-to-end tests. The Python tests drive it over HTTP:
//
//	GET  /start?binding=redirect|post[&sign=1][&force=1][&acs=URL]  returns the authentication request to send to the identity
//	                                                      provider: {"url": ...} or {"url": ..., "form": {...}}
//	POST /acs                                             checks a response (form field SAMLResponse) and returns
//	                                                      {"name_id": ..., "attributes": {...}} or {"error": ...}
//
// Its key and certificate are the files given, so the identity provider can be configured with the certificate.
package main

import (
	"crypto"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"flag"
	"log"
	"net/http"
	"net/url"
	"os"
	"sync"

	"github.com/beevik/etree"

	saml "authelia.com/provider/saml"
)

const signatureMethodRSASHA256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

func main() {
	var (
		listen, entityID, acs, metadataPath, keyPath, certPath string
	)

	flag.StringVar(&listen, "listen", "127.0.0.1:9092", "the address to listen on")
	flag.StringVar(&entityID, "entity-id", "https://sp.example.com/saml/metadata", "the entity ID of the service provider")
	flag.StringVar(&acs, "acs", "https://sp.example.com/saml/acs", "the assertion consumer service URL")
	flag.StringVar(&metadataPath, "idp-metadata", "", "the file holding the metadata of the identity provider")
	flag.StringVar(&keyPath, "key", "", "the PEM key of the service provider")
	flag.StringVar(&certPath, "cert", "", "the PEM certificate of the service provider")
	flag.Parse()

	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		log.Fatalf("loading the key pair: %v", err)
	}

	data, err := os.ReadFile(metadataPath)
	if err != nil {
		log.Fatalf("reading the metadata: %v", err)
	}

	metadata := &saml.EntityDescriptor{}
	if err = xml.Unmarshal(data, metadata); err != nil {
		log.Fatalf("parsing the metadata: %v", err)
	}

	acsURL, _ := url.Parse(acs)
	entityURL, _ := url.Parse(entityID)

	sp := &saml.ServiceProvider{
		EntityID:    entityID,
		Key:         pair.PrivateKey.(crypto.Signer),
		Certificate: pair.Leaf,
		MetadataURL: *entityURL,
		AcsURL:      *acsURL,
		IDPMetadata: metadata,
	}

	if sp.Certificate == nil {
		log.Fatal("the certificate could not be parsed")
	}

	t := &tracker{sp: sp, acsURL: acsURL}

	http.HandleFunc("GET /start", t.start)
	http.HandleFunc("POST /acs", t.acs)

	log.Printf("listening on %s", listen)
	log.Fatal(http.ListenAndServe(listen, nil)) //nolint:gosec // A test server on the loopback address.
}

// tracker is the service provider with the identifiers of the requests it sent.
type tracker struct {
	sp     *saml.ServiceProvider
	acsURL *url.URL

	mu  sync.Mutex
	ids []string
}

func (t *tracker) start(w http.ResponseWriter, r *http.Request) {
	s := *t.sp

	if r.URL.Query().Get("sign") == "1" {
		s.SignatureMethod = signatureMethodRSASHA256
	}

	if r.URL.Query().Get("force") == "1" {
		s.ForceAuthn = new(true)
	}

	if acs := r.URL.Query().Get("acs"); acs != "" {
		u, err := url.Parse(acs)
		if err != nil {
			reply(w, map[string]any{"error": err.Error()})

			return
		}

		s.AcsURL = *u
	}

	binding := saml.HTTPRedirectBinding
	if r.URL.Query().Get("binding") == "post" {
		binding = saml.HTTPPostBinding
	}

	req, err := s.MakeAuthenticationRequest(s.GetSSOBindingLocation(binding), binding, saml.HTTPPostBinding)
	if err != nil {
		reply(w, map[string]any{"error": err.Error()})

		return
	}

	t.mu.Lock()
	t.ids = append(t.ids, req.ID)
	t.mu.Unlock()

	if binding == saml.HTTPPostBinding {
		replyPost(w, &s, req)

		return
	}

	u, err := req.Redirect("relay-1", &s)
	if err != nil {
		reply(w, map[string]any{"error": err.Error()})

		return
	}

	reply(w, map[string]any{"url": u.String()})
}

func replyPost(w http.ResponseWriter, s *saml.ServiceProvider, req *saml.AuthnRequest) {
	if s.SignatureMethod != "" {
		if err := s.SignAuthnRequest(req); err != nil {
			reply(w, map[string]any{"error": err.Error()})

			return
		}
	}

	doc := etree.NewDocument()
	doc.SetRoot(req.Element())

	data, err := doc.WriteToBytes()
	if err != nil {
		reply(w, map[string]any{"error": err.Error()})

		return
	}

	form := map[string]string{"SAMLRequest": base64.StdEncoding.EncodeToString(data), "RelayState": "relay-1"}

	reply(w, map[string]any{"url": req.Destination, "form": form})
}

func (t *tracker) acs(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		reply(w, map[string]any{"error": err.Error()})

		return
	}

	// The request arrives over plain HTTP from the test, so it is presented at the configured URL.
	r.URL = t.acsURL

	t.mu.Lock()
	possible := append([]string(nil), t.ids...)
	t.mu.Unlock()

	assertion, err := t.sp.ParseResponse(r, possible)
	if err != nil {
		reply(w, map[string]any{"error": err.Error(), "status": statusOf(err), "status_codes": statusCodes(r.PostForm.Get("SAMLResponse"))})

		return
	}

	attributes := map[string][]string{}

	for _, statement := range assertion.AttributeStatements {
		for _, attribute := range statement.Attributes {
			for _, value := range attribute.Values {
				attributes[attribute.Name] = append(attributes[attribute.Name], value.Value)
			}
		}
	}

	out := map[string]any{"attributes": attributes}

	if assertion.Subject != nil && assertion.Subject.NameID != nil {
		out["name_id"], out["name_id_format"] = assertion.Subject.NameID.Value, assertion.Subject.NameID.Format
	}

	if len(assertion.AuthnStatements) != 0 && assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef != nil {
		out["authn_context"] = assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value
	}

	reply(w, out)
}

func statusOf(err error) string {
	var invalid *saml.InvalidResponseError

	if e, ok := err.(*saml.InvalidResponseError); ok { //nolint:errorlint // The library returns it unwrapped.
		invalid = e

		return invalid.PrivateErr.Error()
	}

	return ""
}

// statusCodes returns the status codes of a response, for a test to tell refusals apart.
func statusCodes(response string) (codes []string) {
	data, err := base64.StdEncoding.DecodeString(response)
	if err != nil {
		return nil
	}

	doc := etree.NewDocument()
	if err = doc.ReadFromBytes(data); err != nil {
		return nil
	}

	for _, element := range doc.FindElements("//StatusCode") {
		codes = append(codes, element.SelectAttrValue("Value", ""))
	}

	return codes
}

func reply(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")

	_ = json.NewEncoder(w).Encode(value)
}
