---
# SPDX-FileCopyrightText: 2026 Authelia
#
# SPDX-License-Identifier: Apache-2.0

title: "SAML 2.0 Identity Provider"
description: "Configuring the Authelia SAML 2.0 Identity Provider: the signing key, the service providers, and service provider initiated single sign-on."
summary: "Authelia can operate as a SAML 2.0 Identity Provider for service provider initiated single sign-on. This section describes how to configure this."
date: 2026-11-24T00:00:00+01:00
draft: false
images: []
weight: 110300
toc: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  noindex: false # false (default) or true
---

Authelia answers SAML 2.0 authentication requests of the service providers configured here (service provider initiated
single sign-on, HTTP-Redirect and HTTP-POST bindings). A user without a session, or whose session doesn't satisfy the
service provider's authorization policy, logs in at the portal first, and the request is then answered with a page which
posts the response to the service provider.

## Configuration

{{< config-alert-example >}}

```yaml {title="configuration.yml"}
identity_providers:
  saml:
    entity_id: ''
    key: |
      -----BEGIN PRIVATE KEY-----
      ...
      -----END PRIVATE KEY-----
    certificate_chain: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
    assertion_lifespan: '5m'
    enable_keycloak_endpoints: false
    service_providers:
      - entity_id: 'https://sp.example.com/saml/metadata'
        description: 'Example'
        assertion_consumer_service_urls:
          - 'https://sp.example.com/saml/acs'
        certificate: ''
        name_id_format: 'email'
        authorization_policy: 'two_factor'
        groups: []
        sign: 'both'
        attributes: []
```

## Endpoints

SAML is served at each `authelia_url` of the [session cookies](../session/introduction.md), which is the issuer, and
nowhere else (other hosts get `404 Not Found`):

| Endpoint                  | Path                                                                    |
|:-------------------------:|:-----------------------------------------------------------------------:|
| Metadata                  | `/api/saml/metadata` (and `/protocol/saml/descriptor`)                  |
| Single sign-on            | `/api/saml/sso` (and `/protocol/saml`)                                  |

The paths in parentheses are Keycloak's, served when [enable_keycloak_endpoints](#enable_keycloak_endpoints) is set.

## Options

### entity_id

{{< confkey type="string" required="no" >}}

The entity ID of the identity provider, which service providers know it by. Defaults to the issuer, the `authelia_url`
the request was made at.

### key

{{< confkey type="string" required="yes" >}}

The private key which signs the responses and assertions, in PEM format: an RSA key of at least 2048 bits, or an ECDSA
key. Responses are signed with RSA-SHA256 for an RSA key.

### certificate_chain

{{< confkey type="string" required="yes" >}}

The certificate chain of the [key](#key) in PEM format, which the metadata publishes and service providers verify the
signatures with. The first certificate must be the key's.

### assertion_lifespan

{{< confkey type="string,integer" syntax="duration" default="5 minutes" required="no" >}}

How long an assertion is valid after it is made.

### enable_keycloak_endpoints

{{< confkey type="boolean" default="false" required="no" >}}

Also serves the metadata at `/protocol/saml/descriptor` and single sign-on at `/protocol/saml`, Keycloak's paths below a
realm, and publishes these in the metadata. Service providers moved from Keycloak keep their configured URLs, and those
which check the `Destination` of a response against the single sign-on URL keep working, when Authelia is served at the
realm's URL (for example with a `server.address` path of `/realms/<realm>`).

### service_providers

{{< confkey type="list(object)" required="yes" >}}

The service providers which may use the identity provider. A request of any other service provider is refused.

#### entity_id

{{< confkey type="string" required="yes" >}}

The entity ID of the service provider, the `Issuer` of its requests. Must be unique.

#### description

{{< confkey type="string" required="no" >}}

A description of the service provider for administrators.

#### assertion_consumer_service_urls

{{< confkey type="list(string)" required="yes" >}}

The `https` URLs the responses may be posted to (HTTP-POST binding). A request for any other URL is refused. The first
one is the default.

#### certificate

{{< confkey type="string" required="no" >}}

The signing certificate of the service provider in PEM format. When set, its authentication requests must be signed
with it.

#### name_id_format

{{< confkey type="string" default="email" required="no" >}}

The format and value of the `NameID`: `email` (`urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`, the user's
email) or `unspecified` (the username). The format is used whatever format the request asks for, as Keycloak's
"force name ID format".

#### authorization_policy

{{< confkey type="string" default="two_factor" required="no" >}}

The authentication level a user needs: `one_factor` or `two_factor`.

#### groups

{{< confkey type="list(string)" required="no" >}}

When set, only members of one of these groups get an assertion; other users get a `RequestDenied` status. The groups are
read from the user at every request.

#### sign

{{< confkey type="string" default="both" required="no" >}}

What is signed: `both` (the response and the assertion), `response`, or `assertion`.

#### attributes

{{< confkey type="list(string)" required="no" >}}

The user attributes released to the service provider, with their names as the SAML attribute names: `username`,
`email`, `name`, `given_name`, `family_name`, and `groups`. None are released by default.

## Notes

- Only service provider initiated single sign-on is supported. Responses aren't encrypted.
- A request with `ForceAuthn` is answered with an `AuthnFailed` status, as the user can't be asked to log in again.
- A pending request is kept in the storage database for 15 minutes while the user logs in, and can be resumed once.
- Disabled and deleted users get no assertion, even with a live session.
