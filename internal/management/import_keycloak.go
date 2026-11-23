// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package management

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/authelia/authelia/v4/internal/model"
)

const (
	// AuditActionUserImport is the audit action of a user imported from another system.
	AuditActionUserImport = "user.import"

	// ImportSourceKeycloak is the source of credentials imported from Keycloak.
	ImportSourceKeycloak = "keycloak"

	keycloakCredentialPassword             = "password"
	keycloakCredentialWebAuthn             = "webauthn"
	keycloakCredentialWebAuthnPasswordless = "webauthn-passwordless" //nolint:gosec // This is a Keycloak credential type, not a credential.
	keycloakCredentialPasswordHistory      = "password-history"

	webauthnDescriptionMaxLength = 64
)

// KeycloakImportOptions are the options of an import from a Keycloak realm export.
type KeycloakImportOptions struct {
	// RPID is the WebAuthn relying party ID the passkeys were registered for, which must be the RP ID of this Authelia.
	// It is required when the export has WebAuthn credentials.
	RPID string

	// SkipUnsupported skips the users, credentials, and groups which can't be imported and reports them, instead of
	// failing the import.
	SkipUnsupported bool

	// Apply commits the import. Without it the import runs in a transaction which is rolled back: a dry run which
	// checks everything the import would do against the database.
	Apply bool
}

// KeycloakImportReport counts what an import from Keycloak did, or would do in a dry run. It never has secrets.
type KeycloakImportReport struct {
	Applied     bool           `json:"applied"`
	Users       int            `json:"users"`
	Disabled    int            `json:"disabled"`
	Groups      int            `json:"groups"`
	Memberships int            `json:"memberships"`
	Passwords   map[string]int `json:"passwords"`
	WebAuthn    map[string]int `json:"webauthn"`
	Subjects    int            `json:"subjects"`
	Skipped     []string       `json:"skipped,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
}

// keycloakExport is the part of a Keycloak realm export the import reads: the users and the groups. The rest of the
// export, such as the realm keys and the client secrets, is never decoded.
type keycloakExport struct {
	Users  []keycloakUser  `json:"users"`
	Groups []keycloakGroup `json:"groups"`

	// The RP IDs of the realm's WebAuthn policies, empty when Keycloak used its hostname.
	WebAuthnPolicyRPID             string `json:"webAuthnPolicyRpId"`
	WebAuthnPolicyPasswordlessRPID string `json:"webAuthnPolicyPasswordlessRpId"`
}

type keycloakGroup struct {
	Name      string          `json:"name"`
	Path      string          `json:"path"`
	SubGroups []keycloakGroup `json:"subGroups"`
}

type keycloakUser struct {
	ID                     string               `json:"id"`
	Username               string               `json:"username"`
	Email                  string               `json:"email"`
	EmailVerified          bool                 `json:"emailVerified"`
	FirstName              string               `json:"firstName"`
	LastName               string               `json:"lastName"`
	Enabled                bool                 `json:"enabled"`
	FederationLink         string               `json:"federationLink"`
	ServiceAccountClientID string               `json:"serviceAccountClientId"`
	RequiredActions        []string             `json:"requiredActions"`
	Groups                 []string             `json:"groups"`
	Credentials            []keycloakCredential `json:"credentials"`
}

type keycloakCredential struct {
	ID             string `json:"id"`
	Type           string `json:"type"`
	UserLabel      string `json:"userLabel"`
	CreatedDate    int64  `json:"createdDate"`
	SecretData     string `json:"secretData"`
	CredentialData string `json:"credentialData"`
}

type keycloakPasswordSecret struct {
	Value string `json:"value"`
	Salt  string `json:"salt"`
}

type keycloakPasswordData struct {
	HashIterations       int                 `json:"hashIterations"`
	Algorithm            string              `json:"algorithm"`
	AdditionalParameters map[string][]string `json:"additionalParameters"`
}

type keycloakWebAuthnData struct {
	AAGUID                     string   `json:"aaguid"`
	CredentialID               string   `json:"credentialId"`
	Counter                    uint32   `json:"counter"`
	CredentialPublicKey        string   `json:"credentialPublicKey"`
	AttestationStatementFormat string   `json:"attestationStatementFormat"`
	Transports                 []string `json:"transports"`
}

// importUser is a user of the export converted for Authelia.
type importUser struct {
	in       NewUser
	subject  uuid.UUID
	webauthn []model.WebAuthnCredential
	password string
}

// ErrImportRolledBack is returned by a dry run, after which nothing is kept.
var ErrImportRolledBack = errors.New("dry run: rolled back")

// ImportKeycloak imports the users and groups of a Keycloak realm export (kc.sh export --users same_file): the groups,
// the users with their group memberships, their Keycloak user IDs as their OpenID Connect 1.0 subject identifiers (so
// the subject of every client using public subjects stays the same), their password hashes, and their WebAuthn
// credentials with the user handle Keycloak gave them. Everything is imported in one transaction, which a dry run
// rolls back. Existing users and groups are never changed: a username or email which exists fails the import.
func (s *Service) ImportKeycloak(ctx context.Context, r io.Reader, opts KeycloakImportOptions) (report *KeycloakImportReport, err error) {
	var export keycloakExport

	if err = json.NewDecoder(r).Decode(&export); err != nil {
		return nil, fmt.Errorf("%w: the file is not a Keycloak realm export: %w", ErrInvalid, err)
	}

	report = &KeycloakImportReport{Passwords: map[string]int{}, WebAuthn: map[string]int{}}

	// A passkey only works for the RP ID it was registered for, so a realm which set one must be imported for it.
	for _, rpid := range []string{export.WebAuthnPolicyRPID, export.WebAuthnPolicyPasswordlessRPID} {
		if rpid != "" && opts.RPID != "" && !strings.EqualFold(rpid, opts.RPID) {
			return nil, fmt.Errorf("%w: the realm's WebAuthn credentials were registered for the RP ID '%s', not '%s'", ErrInvalid, rpid, opts.RPID)
		}
	}

	groups, err := keycloakGroups(export.Groups, opts, report)
	if err != nil {
		return nil, err
	}

	users := make([]importUser, 0, len(export.Users))

	for i := range export.Users {
		var user *importUser

		if user, err = keycloakImportUser(&export.Users[i], groups, opts, report); err != nil {
			return nil, err
		}

		if user != nil {
			users = append(users, *user)
		}
	}

	if err = s.store.LoadAuthenticationUserHMACKey(ctx); err != nil {
		return nil, err
	}

	err = s.transaction(ctx, func(ctx context.Context) (err error) {
		if err = s.importKeycloak(ctx, groups, users, opts, report); err != nil {
			return err
		}

		if !opts.Apply {
			return ErrImportRolledBack
		}

		return nil
	})

	switch {
	case errors.Is(err, ErrImportRolledBack):
		return report, nil
	case err != nil:
		return nil, wrap(err)
	}

	report.Applied = true

	return report, nil
}

func (s *Service) importKeycloak(ctx context.Context, groups []string, users []importUser, opts KeycloakImportOptions, report *KeycloakImportReport) (err error) {
	for _, group := range groups {
		if err = s.CreateGroup(ctx, group); err != nil {
			return fmt.Errorf("group '%s': %w", group, err)
		}

		report.Groups++
	}

	for _, user := range users {
		if _, err = s.CreateUser(ctx, user.in); err != nil {
			return fmt.Errorf("user '%s': %w", user.in.Username, err)
		}

		username := model.CanonicalAuthenticationUsername(user.in.Username)

		if err = s.store.SaveUserOpaqueIdentifier(ctx, model.UserOpaqueIdentifier{Service: "openid", Username: username, Identifier: user.subject}); err != nil {
			return fmt.Errorf("user '%s': %w", username, err)
		}

		report.Subjects++

		if len(user.webauthn) != 0 {
			if err = s.store.SaveWebAuthnUser(ctx, model.WebAuthnUser{RPID: opts.RPID, Username: username, UserID: user.subject.String()}); err != nil {
				return fmt.Errorf("user '%s': %w", username, err)
			}

			for _, credential := range user.webauthn {
				credential.Username = username

				if err = s.store.SaveWebAuthnCredential(ctx, credential); err != nil {
					return fmt.Errorf("user '%s': %w", username, err)
				}

				if err = s.store.SaveWebAuthnCredentialImported(ctx, credential.KID.String(), ImportSourceKeycloak); err != nil {
					return fmt.Errorf("user '%s': %w", username, err)
				}
			}
		}

		if err = s.audit(ctx, AuditActionUserImport, username, "", map[string]any{"source": ImportSourceKeycloak, "password": user.password, "webauthn": len(user.webauthn)}); err != nil {
			return err
		}

		report.Users++
		report.Memberships += len(user.in.Groups)

		if user.in.Disabled {
			report.Disabled++
		}
	}

	return nil
}

// keycloakGroups returns the names of the groups of the export. Authelia's groups are flat, so a subgroup can't be
// imported.
func keycloakGroups(groups []keycloakGroup, opts KeycloakImportOptions, report *KeycloakImportReport) (names []string, err error) {
	for _, group := range groups {
		for _, sub := range group.SubGroups {
			if err = unsupported(opts, report, fmt.Sprintf("group '%s': the subgroup '%s' can't be imported, as groups are flat", group.Name, sub.Path)); err != nil {
				return nil, err
			}
		}

		if err = validateGroup(group.Name); err != nil {
			if err = unsupported(opts, report, fmt.Sprintf("group '%s': %v", group.Name, err)); err != nil {
				return nil, err
			}

			continue
		}

		names = append(names, group.Name)
	}

	return names, nil
}

// keycloakImportUser converts a user of the export, or returns nil for a user which is skipped.
func keycloakImportUser(user *keycloakUser, groups []string, opts KeycloakImportOptions, report *KeycloakImportReport) (out *importUser, err error) {
	name := fmt.Sprintf("user '%s'", user.Username)

	switch {
	case user.ServiceAccountClientID != "":
		report.Skipped = append(report.Skipped, name+": a service account of a client")

		return nil, nil
	case user.FederationLink != "":
		return nil, unsupported(opts, report, name+": federated users (LDAP or another user storage) can't be imported")
	}

	subject, err := uuid.Parse(user.ID)
	if err != nil {
		return nil, unsupported(opts, report, name+": the user ID is not a UUID, so it can't be the subject identifier")
	}

	// Checked here, rather than when the user is created, so a user Authelia can't hold is reported like the rest.
	if err = validateUsername(model.CanonicalAuthenticationUsername(user.Username)); err != nil {
		return nil, unsupported(opts, report, fmt.Sprintf("%s: %v", name, err))
	}

	if err = validateProfile(model.CanonicalAuthenticationUsername(user.Email), strings.TrimSpace(user.FirstName+" "+user.LastName), strings.TrimSpace(user.FirstName), strings.TrimSpace(user.LastName)); err != nil {
		return nil, unsupported(opts, report, fmt.Sprintf("%s: %v", name, err))
	}

	out = &importUser{
		subject: subject,
		in: NewUser{
			Username:    user.Username,
			Email:       user.Email,
			DisplayName: strings.TrimSpace(user.FirstName + " " + user.LastName),
			GivenName:   user.FirstName,
			FamilyName:  user.LastName,
			Disabled:    !user.Enabled,
		},
		password: "none",
	}

	if user.Email != "" && !user.EmailVerified {
		report.Warnings = append(report.Warnings, name+": the email is not verified in Keycloak")
	}

	if len(user.RequiredActions) != 0 {
		report.Warnings = append(report.Warnings, fmt.Sprintf("%s: the Keycloak required actions %s are not imported", name, strings.Join(user.RequiredActions, ", ")))
	}

	for _, path := range user.Groups {
		group := strings.TrimPrefix(path, "/")

		if !slices.Contains(groups, group) {
			if err = unsupported(opts, report, fmt.Sprintf("%s: the group '%s' is not imported", name, path)); err != nil {
				return nil, err
			}

			continue
		}

		out.in.Groups = append(out.in.Groups, group)
	}

	if err = keycloakImportCredentials(user, out, opts, report); err != nil {
		return nil, err
	}

	return out, nil
}

func keycloakImportCredentials(user *keycloakUser, out *importUser, opts KeycloakImportOptions, report *KeycloakImportReport) (err error) {
	name := fmt.Sprintf("user '%s'", user.Username)
	descriptions := map[string]bool{}

	for _, credential := range user.Credentials {
		switch credential.Type {
		case keycloakCredentialPassword:
			var (
				digest, algorithm string
			)

			if digest, algorithm, err = keycloakPasswordDigest(credential); err != nil {
				if err = unsupported(opts, report, fmt.Sprintf("%s: the password can't be imported: %v", name, err)); err != nil {
					return err
				}

				continue
			}

			if out.in.Digest != "" {
				return fmt.Errorf("%w: %s: the user has more than one password", ErrInvalid, name)
			}

			out.in.Digest, out.password = digest, algorithm
			report.Passwords[algorithm]++
		case keycloakCredentialWebAuthn, keycloakCredentialWebAuthnPasswordless:
			if opts.RPID == "" {
				return fmt.Errorf("%w: %s: the WebAuthn RP ID is required to import WebAuthn credentials", ErrInvalid, name)
			}

			var c *model.WebAuthnCredential

			if c, err = keycloakWebAuthnCredential(credential, opts.RPID, descriptions); err != nil {
				if err = unsupported(opts, report, fmt.Sprintf("%s: a WebAuthn credential can't be imported: %v", name, err)); err != nil {
					return err
				}

				continue
			}

			out.webauthn = append(out.webauthn, *c)
			report.WebAuthn[credential.Type]++
		case keycloakCredentialPasswordHistory:
			// Former passwords only serve Keycloak's password history policy; they can't log in.
			report.Warnings = append(report.Warnings, name+": the password history is not imported")
		default:
			if err = unsupported(opts, report, fmt.Sprintf("%s: the credential type '%s' can't be imported", name, credential.Type)); err != nil {
				return err
			}
		}
	}

	return nil
}

// keycloakPasswordDigest converts a Keycloak password hash to the PHC string format, and returns its algorithm.
func keycloakPasswordDigest(credential keycloakCredential) (digest, algorithm string, err error) {
	var (
		secret keycloakPasswordSecret
		data   keycloakPasswordData
	)

	if err = json.Unmarshal([]byte(credential.SecretData), &secret); err != nil {
		return "", "", fmt.Errorf("the secret data is not valid: %w", err)
	}

	if err = json.Unmarshal([]byte(credential.CredentialData), &data); err != nil {
		return "", "", fmt.Errorf("the credential data is not valid: %w", err)
	}

	var hash, salt []byte

	if hash, err = base64.StdEncoding.DecodeString(secret.Value); err != nil || len(hash) == 0 {
		return "", "", fmt.Errorf("the hash is not valid base64")
	}

	if salt, err = base64.StdEncoding.DecodeString(secret.Salt); err != nil || len(salt) == 0 {
		return "", "", fmt.Errorf("the salt is not valid base64")
	}

	if data.HashIterations <= 0 {
		return "", "", fmt.Errorf("the iterations are not valid")
	}

	switch data.Algorithm {
	case "argon2":
		return keycloakArgon2Digest(hash, salt, data)
	case "pbkdf2", "pbkdf2-sha256", "pbkdf2-sha512":
		variant := data.Algorithm
		if variant == "pbkdf2" {
			variant = "pbkdf2-sha1"
		}

		// Authelia's PBKDF2 digests use the adapted base64 encoding of passlib: '.' for '+' and no padding.
		adapted := func(b []byte) string {
			return strings.ReplaceAll(base64.RawStdEncoding.EncodeToString(b), "+", ".")
		}

		phc := "$pbkdf2"
		if variant != "pbkdf2-sha1" {
			phc = "$" + variant
		}

		return fmt.Sprintf("%s$%d$%s$%s", phc, data.HashIterations, adapted(salt), adapted(hash)), variant, nil
	default:
		return "", "", fmt.Errorf("the algorithm '%s' is not supported", data.Algorithm)
	}
}

func keycloakArgon2Digest(hash, salt []byte, data keycloakPasswordData) (digest, algorithm string, err error) {
	parameter := func(name, fallback string) string {
		if values := data.AdditionalParameters[name]; len(values) != 0 {
			return values[0]
		}

		return fallback
	}

	variant := map[string]string{"id": "argon2id", "i": "argon2i", "d": "argon2d"}[parameter("type", "id")]
	if variant == "" {
		return "", "", fmt.Errorf("the argon2 type '%s' is not supported", parameter("type", ""))
	}

	if version := parameter("version", "1.3"); version != "1.3" {
		return "", "", fmt.Errorf("the argon2 version '%s' is not supported", version)
	}

	var memory, parallelism, length int

	if memory, err = strconv.Atoi(parameter("memory", "7168")); err != nil || memory <= 0 {
		return "", "", fmt.Errorf("the argon2 memory is not valid")
	}

	if parallelism, err = strconv.Atoi(parameter("parallelism", "1")); err != nil || parallelism <= 0 {
		return "", "", fmt.Errorf("the argon2 parallelism is not valid")
	}

	if length, err = strconv.Atoi(parameter("hashLength", "32")); err != nil || length != len(hash) {
		return "", "", fmt.Errorf("the argon2 hash length doesn't match the hash")
	}

	return fmt.Sprintf("$%s$v=19$m=%d,t=%d,p=%d$%s$%s", variant, memory, data.HashIterations, parallelism,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(hash)), variant, nil
}

// keycloakWebAuthnCredential converts a Keycloak WebAuthn credential. Keycloak doesn't keep the backup eligible and
// backup state flags, so they are adopted at the first sign in (the import marks the credential).
func keycloakWebAuthnCredential(credential keycloakCredential, rpid string, descriptions map[string]bool) (c *model.WebAuthnCredential, err error) {
	var data keycloakWebAuthnData

	if err = json.Unmarshal([]byte(credential.CredentialData), &data); err != nil {
		return nil, fmt.Errorf("the credential data is not valid: %w", err)
	}

	var kid, key []byte

	if kid, err = decodeBase64Any(data.CredentialID); err != nil || len(kid) == 0 {
		return nil, fmt.Errorf("the credential ID is not valid base64")
	}

	if key, err = decodeBase64Any(data.CredentialPublicKey); err != nil || len(key) == 0 {
		return nil, fmt.Errorf("the public key is not valid base64")
	}

	c = &model.WebAuthnCredential{
		CreatedAt:         time.UnixMilli(credential.CreatedDate).UTC(),
		RPID:              rpid,
		Description:       webauthnDescription(credential.UserLabel, descriptions),
		KID:               model.NewBase64(kid),
		AttestationType:   "none",
		AttestationFormat: data.AttestationStatementFormat,
		Transport:         strings.Join(data.Transports, ","),
		SignCount:         data.Counter,
		Discoverable:      credential.Type == keycloakCredentialWebAuthnPasswordless,
		Present:           true,
		PublicKey:         key,
	}

	if credential.CreatedDate == 0 {
		c.CreatedAt = time.Now().UTC()
	}

	if slices.Contains(data.Transports, "internal") || slices.Contains(data.Transports, "hybrid") {
		c.Attachment = "platform"
	} else {
		c.Attachment = "cross-platform"
	}

	if data.AAGUID != "" {
		var aaguid uuid.UUID

		if aaguid, err = uuid.Parse(data.AAGUID); err != nil {
			return nil, fmt.Errorf("the AAGUID is not valid")
		}

		c.AAGUID = uuid.NullUUID{UUID: aaguid, Valid: true}
	}

	return c, nil
}

// webauthnDescription returns a description which is unique for the user, as Authelia requires.
func webauthnDescription(label string, used map[string]bool) string {
	label = strings.TrimSpace(label)
	if label == "" {
		label = "Keycloak"
	}

	if len(label) > webauthnDescriptionMaxLength-4 {
		label = label[:webauthnDescriptionMaxLength-4]
	}

	description := label

	for i := 2; used[description]; i++ {
		description = fmt.Sprintf("%s (%d)", label, i)
	}

	used[description] = true

	return description
}

// decodeBase64Any decodes the standard or URL-safe base64 encoding, with or without padding, as Keycloak uses both.
func decodeBase64Any(value string) ([]byte, error) {
	value = strings.TrimRight(value, "=")
	value = strings.NewReplacer("-", "+", "_", "/").Replace(value)

	return base64.RawStdEncoding.DecodeString(value)
}

// unsupported reports something which can't be imported: it fails the import, unless it is to be skipped.
func unsupported(opts KeycloakImportOptions, report *KeycloakImportReport, message string) error {
	if !opts.SkipUnsupported {
		return fmt.Errorf("%w: %s (skip it with the option to skip what can't be imported)", ErrInvalid, message)
	}

	report.Skipped = append(report.Skipped, message)

	return nil
}
