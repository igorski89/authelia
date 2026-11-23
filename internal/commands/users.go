// SPDX-FileCopyrightText: 2026 Authelia
//
// SPDX-License-Identifier: Apache-2.0

package commands

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/authelia/authelia/v4/internal/clock"
	"github.com/authelia/authelia/v4/internal/configuration/schema"
	"github.com/authelia/authelia/v4/internal/configuration/validator"
	"github.com/authelia/authelia/v4/internal/management"
	"github.com/authelia/authelia/v4/internal/middlewares"
	"github.com/authelia/authelia/v4/internal/random"
	"github.com/authelia/authelia/v4/internal/session"
	"github.com/authelia/authelia/v4/internal/storage"
)

const (
	cmdFlagNameEmail          = "email"
	cmdFlagNameDisplayName    = "display-name"
	cmdFlagNameGivenName      = "given-name"
	cmdFlagNameFamilyName     = "family-name"
	cmdFlagNameGroup          = "group"
	cmdFlagNameDisabled       = "disabled"
	cmdFlagNameEnable         = "enable"
	cmdFlagNameDisable        = "disable"
	cmdFlagNamePasswordStdin  = "password-stdin"
	cmdFlagNamePasswordDigest = "password-digest"
	cmdFlagNameNoPassword     = "no-password"
	cmdFlagNameLimit          = "limit"
	cmdFlagNamePage           = "page"
	cmdFlagNameClientID       = "client-id"
	cmdFlagNameWebAuthnRPID   = "webauthn-rpid"
	cmdFlagNameApply          = "apply"
	cmdFlagNameSkip           = "skip-unsupported"

	cmdAutheliaUsersShort = "Manage the users of the database authentication backend"
	cmdAutheliaUsersLong  = `Manage the users of the database authentication backend.

These commands change the storage database directly, with the same rules as the administration API. They require the 'authentication_backend.database' configuration and the storage configuration, which may be given with the same flags as the 'authelia storage' commands.`
	cmdAutheliaUsersExample = `authelia users list --config config.yml
authelia users create john --email john@example.com --display-name "John Smith" --group admins --config config.yml
authelia users password john --config config.yml
authelia users update john --disable --config config.yml
authelia users delete john --config config.yml`

	cmdAutheliaGroupsShort = "Manage the groups of the database authentication backend"
	cmdAutheliaGroupsLong  = `Manage the groups of the database authentication backend.

These commands change the storage database directly, with the same rules as the administration API. They require the 'authentication_backend.database' configuration and the storage configuration, which may be given with the same flags as the 'authelia storage' commands.`
	cmdAutheliaGroupsExample = `authelia groups list --config config.yml
authelia groups create admins --config config.yml
authelia groups add admins john jane --config config.yml
authelia groups members admins --config config.yml`
)

func newUsersCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:               "users",
		Short:             cmdAutheliaUsersShort,
		Long:              cmdAutheliaUsersLong,
		Example:           cmdAutheliaUsersExample,
		PersistentPreRunE: ctx.usersPersistentPreRunE(),
		Args:              cobra.NoArgs,

		DisableAutoGenTag: true,
	}

	addStoragePersistentFlags(cmd)

	cmd.AddCommand(
		newUsersListCmd(ctx),
		newUsersGetCmd(ctx),
		newUsersCreateCmd(ctx),
		newUsersUpdateCmd(ctx),
		newUsersPasswordCmd(ctx),
		newUsersDeleteCmd(ctx),
		newUsersLogoutCmd(ctx),
		newUsersAuditCmd(ctx),
		newUsersImportCmd(ctx),
	)

	return cmd
}

func newGroupsCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:               "groups",
		Short:             cmdAutheliaGroupsShort,
		Long:              cmdAutheliaGroupsLong,
		Example:           cmdAutheliaGroupsExample,
		PersistentPreRunE: ctx.usersPersistentPreRunE(),
		Args:              cobra.NoArgs,

		DisableAutoGenTag: true,
	}

	addStoragePersistentFlags(cmd)

	cmd.AddCommand(
		newSimpleCmd("list", "List the groups", cobra.NoArgs, ctx.GroupsListRunE),
		newSimpleCmd("create <name>", "Create a group", cobra.ExactArgs(1), ctx.GroupsCreateRunE),
		newSimpleCmd("delete <name>", "Delete a group and its memberships", cobra.ExactArgs(1), ctx.GroupsDeleteRunE),
		newSimpleCmd("members <name>", "List the members of a group", cobra.ExactArgs(1), ctx.GroupsMembersRunE),
		newSimpleCmd("add <name> <username>...", "Add users to a group", cobra.MinimumNArgs(2), ctx.GroupsAddRunE),
		newSimpleCmd("remove <name> <username>...", "Remove users from a group", cobra.MinimumNArgs(2), ctx.GroupsRemoveRunE),
	)

	return cmd
}

func newSimpleCmd(use, short string, args cobra.PositionalArgs, runE func(cmd *cobra.Command, args []string) error) *cobra.Command {
	return &cobra.Command{
		Use:   use,
		Short: short,
		Args:  args,
		RunE:  runE,

		SilenceUsage:      true,
		DisableAutoGenTag: true,
	}
}

func newUsersImportCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = &cobra.Command{
		Use:   "import",
		Short: "Import users from another identity provider",
		Args:  cobra.NoArgs,

		DisableAutoGenTag: true,
	}

	keycloak := newSimpleCmd("keycloak <realm export file>", "Import the users and groups of a Keycloak realm export", cobra.ExactArgs(1), ctx.UsersImportKeycloakRunE)

	keycloak.Long = `Import the users and groups of a Keycloak realm export.

The file is the export of one realm with its users in the same file: kc.sh export --realm <realm> --users same_file --file <file>. Only its users and groups are read.

Every group is created, and every user with its group memberships, profile, enabled state, password hash (argon2 and pbkdf2, kept as they are), and WebAuthn credentials (passkeys and security keys, with their sign counts). The Keycloak user ID becomes the user's OpenID Connect 1.0 subject identifier (for clients with public subjects) and WebAuthn user handle, so apps see the same subject and passkeys keep working. The backup flags of the WebAuthn credentials, which Keycloak doesn't keep, are taken from their first sign in.

Nothing is changed unless --apply is given: without it the import runs in a transaction which is rolled back, and reports what it would do. With it everything is imported in one transaction, or nothing. An existing username or email fails the import. Anything which can't be imported (one-time password credentials, subgroups, federated users, unknown hash algorithms) fails the import unless --skip-unsupported is given, which reports it instead. Service account users are always skipped.`
	keycloak.Example = `authelia users import keycloak realm-export.json --webauthn-rpid example.com --config config.yml
authelia users import keycloak realm-export.json --webauthn-rpid example.com --apply --config config.yml`

	keycloak.Flags().String(cmdFlagNameWebAuthnRPID, "", "the WebAuthn RP ID the credentials were registered for, which must be Authelia's (required with WebAuthn credentials)")
	keycloak.Flags().Bool(cmdFlagNameApply, false, "import, instead of a dry run")
	keycloak.Flags().Bool(cmdFlagNameSkip, false, "skip and report what can't be imported, instead of failing")

	cmd.AddCommand(keycloak)

	return cmd
}

func newUsersListCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("list", "List the users", cobra.NoArgs, ctx.UsersListRunE)

	cmd.Flags().Int(cmdFlagNameLimit, management.DefaultPageSize, fmt.Sprintf("the number of users to list, at most %d", management.MaxPageSize))
	cmd.Flags().Int(cmdFlagNamePage, 0, "the page of users to list, starting at 0")

	return cmd
}

func newUsersGetCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	return newSimpleCmd("get <username>", "Show a user", cobra.ExactArgs(1), ctx.UsersGetRunE)
}

func newUsersCreateCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("create <username>", "Create a user", cobra.ExactArgs(1), ctx.UsersCreateRunE)

	cmd.Long = `Create a user.

The password is read from the terminal, or from the first line of the standard input with --password-stdin. A password digest in the PHC string format (for example one imported from another system) can be given with --password-digest instead, or the user can be created without a password with --no-password.`

	cmd.Flags().String(cmdFlagNameEmail, "", "the email of the user (required)")
	cmd.Flags().String(cmdFlagNameDisplayName, "", "the display name of the user")
	cmd.Flags().String(cmdFlagNameGivenName, "", "the given name of the user")
	cmd.Flags().String(cmdFlagNameFamilyName, "", "the family name of the user")
	cmd.Flags().StringSlice(cmdFlagNameGroup, nil, "a group to add the user to, which must exist; may be repeated")
	cmd.Flags().Bool(cmdFlagNameDisabled, false, "create the user disabled")
	addUsersPasswordFlags(cmd)

	return cmd
}

func newUsersUpdateCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("update <username>", "Change the profile of a user, or disable or enable it", cobra.ExactArgs(1), ctx.UsersUpdateRunE)

	cmd.Flags().String(cmdFlagNameEmail, "", "the new email of the user")
	cmd.Flags().String(cmdFlagNameDisplayName, "", "the new display name of the user")
	cmd.Flags().String(cmdFlagNameGivenName, "", "the new given name of the user")
	cmd.Flags().String(cmdFlagNameFamilyName, "", "the new family name of the user")
	cmd.Flags().Bool(cmdFlagNameDisable, false, "disable the user")
	cmd.Flags().Bool(cmdFlagNameEnable, false, "enable the user")
	cmd.MarkFlagsMutuallyExclusive(cmdFlagNameDisable, cmdFlagNameEnable)

	return cmd
}

func newUsersPasswordCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("password <username>", "Set or remove the password of a user", cobra.ExactArgs(1), ctx.UsersPasswordRunE)

	cmd.Long = `Set or remove the password of a user.

The password is read from the terminal, or from the first line of the standard input with --password-stdin. A password digest in the PHC string format can be given with --password-digest instead, and --no-password removes the password.`

	addUsersPasswordFlags(cmd)

	return cmd
}

func newUsersDeleteCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("delete <username>", "Delete a user", cobra.ExactArgs(1), ctx.UsersDeleteRunE)

	cmd.Long = `Delete a user.

The user's passkeys and other WebAuthn credentials, TOTP configuration, recovery codes, preferred Duo device, and external identity links are deleted with it. The username can never be used again, so a new user can't inherit anything still keyed by it.`

	cmd.Flags().BoolP(cmdFlagNameForce, "f", false, "delete without confirmation")

	return cmd
}

func newUsersLogoutCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("logout <username>", "End everything a user is logged in with", cobra.ExactArgs(1), ctx.UsersLogoutRunE)

	cmd.Long = `End everything a user is logged in with.

Revokes the user's OAuth 2.0 and OpenID Connect 1.0 tokens and pre-configured consent, and destroys its portal sessions when they are kept in the storage database (the default). With --client-id only the tokens of that client are revoked. Disabling or deleting a user does this too.`

	cmd.Flags().String(cmdFlagNameClientID, "", "only revoke the tokens of this OAuth 2.0 client")

	return cmd
}

func newUsersAuditCmd(ctx *CmdCtx) (cmd *cobra.Command) {
	cmd = newSimpleCmd("audit [username]", "List the changes made to users and groups, newest first", cobra.MaximumNArgs(1), ctx.UsersAuditRunE)

	cmd.Flags().Int(cmdFlagNameLimit, management.DefaultPageSize, fmt.Sprintf("the number of entries to list, at most %d", management.MaxPageSize))
	cmd.Flags().Int(cmdFlagNamePage, 0, "the page of entries to list, starting at 0")

	return cmd
}

func addUsersPasswordFlags(cmd *cobra.Command) {
	cmd.Flags().Bool(cmdFlagNamePasswordStdin, false, "read the password from the first line of the standard input")
	cmd.Flags().String(cmdFlagNamePasswordDigest, "", "a password digest in the PHC string format to store as it is")
	cmd.Flags().Bool(cmdFlagNameNoPassword, false, "no password: create the user without one, or remove it")
	cmd.MarkFlagsMutuallyExclusive(cmdFlagNamePasswordStdin, cmdFlagNamePasswordDigest, cmdFlagNameNoPassword)
}

// usersPersistentPreRunE loads the configuration and the storage like the storage commands, then checks the schema
// and that the database authentication backend is configured.
func (ctx *CmdCtx) usersPersistentPreRunE() func(cmd *cobra.Command, args []string) error {
	return ctx.ChainRunE(
		ctx.ConfigStorageCommandLineConfigRunE,
		ctx.HelperConfigLoadRunE,
		ctx.ConfigValidateStorageRunE,
		ctx.ConfigValidateUsersRunE,
		ctx.LoadProvidersStorageRunE,
		func(_ *cobra.Command, _ []string) error {
			if err := ctx.CheckSchema(); err != nil {
				return storageWrapCheckSchemaErr(err)
			}

			return nil
		},
	)
}

// ConfigValidateUsersRunE validates the database authentication backend and password policy configuration, which
// the users and groups commands depend on.
func (ctx *CmdCtx) ConfigValidateUsersRunE(_ *cobra.Command, _ []string) (err error) {
	if ctx.config.AuthenticationBackend.Database == nil {
		return errors.New("the users and groups commands require the 'authentication_backend.database' configuration")
	}

	validator.ValidatePasswordConfiguration(&ctx.config.AuthenticationBackend.Database.Password, ctx.cconfig.validator)
	validator.ValidatePasswordPolicy(&ctx.config.PasswordPolicy, ctx.cconfig.validator)

	if len(ctx.config.Session.Cookies) != 0 {
		validator.ValidateSession(ctx.config, ctx.cconfig.validator)
	}

	if errs := ctx.cconfig.validator.Errors(); len(errs) != 0 {
		return errors.Join(errs...)
	}

	return nil
}

func (ctx *CmdCtx) managementService() (service *management.Service, err error) {
	var sessions management.Sessions

	if sessions, err = ctx.usersSessions(); err != nil {
		return nil, err
	}

	return management.New(ctx.config.AuthenticationBackend.Database, ctx.providers.StorageProvider, middlewares.NewPasswordPolicyProvider(ctx.config.PasswordPolicy), sessions)
}

// usersSessions returns the portal sessions when they are kept in the storage database, which is the default. Sessions
// kept in a cache can't be reached reliably from the CLI (the memory cache belongs to the running server), so there are
// none and revoking a user leaves its portal sessions; they are refused anyway once the user is disabled or deleted.
func (ctx *CmdCtx) usersSessions() (sessions management.Sessions, err error) {
	switch ctx.config.Session.Storage {
	case schema.SessionStorageInternal, "":
		break
	default:
		return nil, nil
	}

	if len(ctx.config.Session.Cookies) == 0 {
		return nil, nil
	}

	var key []byte

	if key, err = ctx.providers.StorageProvider.LoadHMACKey(ctx, "session", sha256.BlockSize); err != nil {
		return nil, fmt.Errorf("error loading the session key: %w", err)
	}

	var provider session.Provider

	if provider, err = session.NewProvider(ctx.config, key, clock.New(), random.New(), storage.NewSessionRepository(ctx.providers.StorageProvider)); err != nil {
		return nil, fmt.Errorf("error initializing the sessions: %w", err)
	}

	return provider, nil
}

// usersActor returns the context carrying the operating system user running the command as the actor which the audit
// records.
func (ctx *CmdCtx) usersActor() context.Context {
	name := "unknown"

	if u, err := user.Current(); err == nil && u.Username != "" {
		name = u.Username
	}

	return management.WithActor(ctx, "cli:"+name)
}

// withManagementService runs fn with the management service and closes the storage afterwards.
func (ctx *CmdCtx) withManagementService(fn func(service *management.Service) error) (err error) {
	defer func() {
		if closeErr := ctx.providers.StorageProvider.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}()

	var service *management.Service

	if service, err = ctx.managementService(); err != nil {
		return err
	}

	return fn(service)
}

// UsersListRunE is the RunE for the authelia users list command.
func (ctx *CmdCtx) UsersListRunE(cmd *cobra.Command, _ []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		var limit, page int

		if limit, err = cmd.Flags().GetInt(cmdFlagNameLimit); err != nil {
			return err
		}

		if page, err = cmd.Flags().GetInt(cmdFlagNamePage); err != nil {
			return err
		}

		var users []management.User

		if users, err = service.ListUsers(ctx, limit, page); err != nil {
			return err
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)

		_, _ = fmt.Fprintln(w, "USERNAME\tEMAIL\tDISPLAY NAME\tGROUPS\tDISABLED\tPASSWORD")

		for _, user := range users {
			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%t\t%t\n", user.Username, user.Email, user.DisplayName, strings.Join(user.Groups, ","), user.Disabled, user.HasPassword)
		}

		return w.Flush()
	})
}

// UsersGetRunE is the RunE for the authelia users get command.
func (ctx *CmdCtx) UsersGetRunE(cmd *cobra.Command, args []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		var user *management.User

		if user, err = service.GetUser(ctx, args[0]); err != nil {
			return err
		}

		writeUser(cmd.OutOrStdout(), user)

		return nil
	})
}

// UsersCreateRunE is the RunE for the authelia users create command.
func (ctx *CmdCtx) UsersCreateRunE(cmd *cobra.Command, args []string) (err error) {
	in := management.NewUser{Username: args[0]}

	flags := cmd.Flags()

	for name, value := range map[string]*string{cmdFlagNameEmail: &in.Email, cmdFlagNameDisplayName: &in.DisplayName, cmdFlagNameGivenName: &in.GivenName, cmdFlagNameFamilyName: &in.FamilyName} {
		if *value, err = flags.GetString(name); err != nil {
			return err
		}
	}

	if in.Groups, err = flags.GetStringSlice(cmdFlagNameGroup); err != nil {
		return err
	}

	if in.Disabled, err = flags.GetBool(cmdFlagNameDisabled); err != nil {
		return err
	}

	if in.Password, err = readUsersPassword(cmd); err != nil {
		return err
	}

	return ctx.withManagementService(func(service *management.Service) (err error) {
		var user *management.User

		if user, err = service.CreateUser(ctx.usersActor(), in); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created user '%s'.\n\n", user.Username)

		writeUser(cmd.OutOrStdout(), user)

		return nil
	})
}

// UsersUpdateRunE is the RunE for the authelia users update command.
func (ctx *CmdCtx) UsersUpdateRunE(cmd *cobra.Command, args []string) (err error) {
	var changes management.UserChanges

	flags := cmd.Flags()

	for name, value := range map[string]**string{cmdFlagNameEmail: &changes.Email, cmdFlagNameDisplayName: &changes.DisplayName, cmdFlagNameGivenName: &changes.GivenName, cmdFlagNameFamilyName: &changes.FamilyName} {
		if *value, err = changedString(flags, name); err != nil {
			return err
		}
	}

	switch {
	case flags.Changed(cmdFlagNameDisable):
		disabled := true
		changes.Disabled = &disabled
	case flags.Changed(cmdFlagNameEnable):
		disabled := false
		changes.Disabled = &disabled
	}

	return ctx.withManagementService(func(service *management.Service) (err error) {
		var user *management.User

		if user, err = service.UpdateUser(ctx.usersActor(), args[0], changes); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Updated user '%s'.\n\n", user.Username)

		writeUser(cmd.OutOrStdout(), user)

		return nil
	})
}

// UsersPasswordRunE is the RunE for the authelia users password command.
func (ctx *CmdCtx) UsersPasswordRunE(cmd *cobra.Command, args []string) (err error) {
	var password management.Password

	if password, err = readUsersPassword(cmd); err != nil {
		return err
	}

	return ctx.withManagementService(func(service *management.Service) (err error) {
		if err = service.SetPassword(ctx.usersActor(), args[0], password); err != nil {
			return err
		}

		if password == (management.Password{}) {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed the password of user '%s'.\n", args[0])
		} else {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Set the password of user '%s'.\n", args[0])
		}

		return nil
	})
}

// UsersDeleteRunE is the RunE for the authelia users delete command.
func (ctx *CmdCtx) UsersDeleteRunE(cmd *cobra.Command, args []string) (err error) {
	var force bool

	if force, err = cmd.Flags().GetBool(cmdFlagNameForce); err != nil {
		return err
	}

	if !force {
		var confirmed bool

		prompt := fmt.Sprintf("This will delete user '%s' with their second factors, and the username can never be used again; type 'DELETE' and press return to continue: ", args[0])

		if confirmed, err = termReadConfirmation(prompt, "DELETE"); err != nil {
			return err
		}

		if !confirmed {
			return errors.New("cancelling the deletion as it was not confirmed")
		}
	}

	return ctx.withManagementService(func(service *management.Service) (err error) {
		if err = service.DeleteUser(ctx.usersActor(), args[0]); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted user '%s'.\n", args[0])

		return nil
	})
}

// UsersLogoutRunE is the RunE for the authelia users logout command.
func (ctx *CmdCtx) UsersLogoutRunE(cmd *cobra.Command, args []string) (err error) {
	var clientID string

	if clientID, err = cmd.Flags().GetString(cmdFlagNameClientID); err != nil {
		return err
	}

	return ctx.withManagementService(func(service *management.Service) (err error) {
		var revocation *management.Revocation

		if revocation, err = service.RevokeUser(ctx.usersActor(), args[0], clientID); err != nil {
			return err
		}

		writeRevocation(cmd.OutOrStdout(), args[0], revocation)

		return nil
	})
}

func writeRevocation(w io.Writer, username string, revocation *management.Revocation) {
	_, _ = fmt.Fprintf(w, "Revoked %d token session(s) and pre-configured consent(s) of user '%s'.\n", revocation.Tokens, username)

	if revocation.Sessions == nil {
		_, _ = fmt.Fprintln(w, "Portal sessions are kept in a cache this command can't reach; they are refused once the user is disabled or deleted, or use the administration API to end them.")
	} else {
		_, _ = fmt.Fprintf(w, "Destroyed %d portal session(s).\n", *revocation.Sessions)
	}
}

// UsersAuditRunE is the RunE for the authelia users audit command.
func (ctx *CmdCtx) UsersAuditRunE(cmd *cobra.Command, args []string) (err error) {
	var (
		limit, page int
		username    string
	)

	if limit, err = cmd.Flags().GetInt(cmdFlagNameLimit); err != nil {
		return err
	}

	if page, err = cmd.Flags().GetInt(cmdFlagNamePage); err != nil {
		return err
	}

	if len(args) != 0 {
		username = args[0]
	}

	return ctx.withManagementService(func(service *management.Service) (err error) {
		var entries []management.AuditEntry

		if entries, err = service.ListAudit(ctx, username, limit, page); err != nil {
			return err
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)

		_, _ = fmt.Fprintln(w, "TIME\tACTOR\tACTION\tUSERNAME\tGROUP\tDETAILS")

		for _, entry := range entries {
			details := ""

			if len(entry.Details) != 0 {
				data, _ := json.Marshal(entry.Details)
				details = string(data)
			}

			_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n", entry.Time.Format("2006-01-02 15:04:05 MST"), entry.Actor, entry.Action, entry.Username, entry.Group, details)
		}

		return w.Flush()
	})
}

// GroupsListRunE is the RunE for the authelia groups list command.
func (ctx *CmdCtx) GroupsListRunE(cmd *cobra.Command, _ []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		var groups []management.Group

		if groups, err = service.ListGroups(ctx); err != nil {
			return err
		}

		for _, group := range groups {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), group.Name)
		}

		return nil
	})
}

// GroupsCreateRunE is the RunE for the authelia groups create command.
func (ctx *CmdCtx) GroupsCreateRunE(cmd *cobra.Command, args []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		if err = service.CreateGroup(ctx.usersActor(), args[0]); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Created group '%s'.\n", args[0])

		return nil
	})
}

// GroupsDeleteRunE is the RunE for the authelia groups delete command.
func (ctx *CmdCtx) GroupsDeleteRunE(cmd *cobra.Command, args []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		if err = service.DeleteGroup(ctx.usersActor(), args[0]); err != nil {
			return err
		}

		_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Deleted group '%s'.\n", args[0])

		return nil
	})
}

// GroupsMembersRunE is the RunE for the authelia groups members command.
func (ctx *CmdCtx) GroupsMembersRunE(cmd *cobra.Command, args []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		var members []management.User

		if members, err = service.GroupMembers(ctx, args[0]); err != nil {
			return err
		}

		for _, member := range members {
			_, _ = fmt.Fprintln(cmd.OutOrStdout(), member.Username)
		}

		return nil
	})
}

// GroupsAddRunE is the RunE for the authelia groups add command.
func (ctx *CmdCtx) GroupsAddRunE(cmd *cobra.Command, args []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		for _, username := range args[1:] {
			if err = service.AddUserToGroup(ctx.usersActor(), username, args[0]); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Added user '%s' to group '%s'.\n", username, args[0])
		}

		return nil
	})
}

// GroupsRemoveRunE is the RunE for the authelia groups remove command.
func (ctx *CmdCtx) GroupsRemoveRunE(cmd *cobra.Command, args []string) (err error) {
	return ctx.withManagementService(func(service *management.Service) (err error) {
		for _, username := range args[1:] {
			if err = service.RemoveUserFromGroup(ctx.usersActor(), username, args[0]); err != nil {
				return err
			}

			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "Removed user '%s' from group '%s'.\n", username, args[0])
		}

		return nil
	})
}

// readUsersPassword reads the password the password flags ask for: a digest, none, the first line of the standard
// input, or a password typed twice in the terminal.
func readUsersPassword(cmd *cobra.Command) (password management.Password, err error) {
	flags := cmd.Flags()

	if password.Digest, err = flags.GetString(cmdFlagNamePasswordDigest); err != nil || password.Digest != "" {
		return password, err
	}

	var none, stdin bool

	if none, err = flags.GetBool(cmdFlagNameNoPassword); err != nil || none {
		return password, err
	}

	if stdin, err = flags.GetBool(cmdFlagNamePasswordStdin); err != nil {
		return password, err
	}

	if stdin {
		if password.Plain, err = readFirstLine(cmd.InOrStdin()); err != nil {
			return password, fmt.Errorf("failed to read the password from the standard input: %w", err)
		}

		return password, nil
	}

	var confirmation string

	if password.Plain, err = termReadPasswordWithPrompt("Enter Password: ", cmdFlagNamePasswordStdin); err != nil {
		return password, err
	}

	if confirmation, err = termReadPasswordWithPrompt("Confirm Password: ", cmdFlagNamePasswordStdin); err != nil {
		return password, err
	}

	if password.Plain != confirmation {
		return password, errors.New("the password and its confirmation do not match")
	}

	return password, nil
}

func readFirstLine(r io.Reader) (line string, err error) {
	scanner := bufio.NewScanner(r)

	if !scanner.Scan() {
		if err = scanner.Err(); err != nil {
			return "", err
		}

		return "", errors.New("the standard input is empty")
	}

	return strings.TrimRight(scanner.Text(), "\r"), nil
}

func changedString(flags *pflag.FlagSet, name string) (value *string, err error) {
	if !flags.Changed(name) {
		return nil, nil
	}

	var v string

	if v, err = flags.GetString(name); err != nil {
		return nil, err
	}

	return &v, nil
}

func writeUser(w io.Writer, user *management.User) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(tw, "Username:\t%s\n", user.Username)
	_, _ = fmt.Fprintf(tw, "Email:\t%s\n", user.Email)
	_, _ = fmt.Fprintf(tw, "Display Name:\t%s\n", user.DisplayName)
	_, _ = fmt.Fprintf(tw, "Given Name:\t%s\n", user.GivenName)
	_, _ = fmt.Fprintf(tw, "Family Name:\t%s\n", user.FamilyName)
	_, _ = fmt.Fprintf(tw, "Groups:\t%s\n", strings.Join(user.Groups, ", "))
	_, _ = fmt.Fprintf(tw, "Disabled:\t%t\n", user.Disabled)
	_, _ = fmt.Fprintf(tw, "Has Password:\t%t\n", user.HasPassword)
	_, _ = fmt.Fprintf(tw, "Credentials:\t%s\n", strings.Join(user.Credentials, ", "))

	if user.Sessions != nil {
		_, _ = fmt.Fprintf(tw, "Sessions:\t%d\n", *user.Sessions)
	}

	_, _ = fmt.Fprintf(tw, "Created:\t%s\n", user.CreatedAt.Format("2006-01-02 15:04:05 MST"))
	_, _ = fmt.Fprintf(tw, "Updated:\t%s\n", user.UpdatedAt.Format("2006-01-02 15:04:05 MST"))

	_ = tw.Flush()
}

// UsersImportKeycloakRunE is the RunE for the authelia users import keycloak command.
func (ctx *CmdCtx) UsersImportKeycloakRunE(cmd *cobra.Command, args []string) (err error) {
	opts := management.KeycloakImportOptions{}

	if opts.RPID, err = cmd.Flags().GetString(cmdFlagNameWebAuthnRPID); err != nil {
		return err
	}

	if opts.Apply, err = cmd.Flags().GetBool(cmdFlagNameApply); err != nil {
		return err
	}

	if opts.SkipUnsupported, err = cmd.Flags().GetBool(cmdFlagNameSkip); err != nil {
		return err
	}

	if err = ctx.usersImportCheckRPID(opts.RPID); err != nil {
		return err
	}

	file, err := os.Open(args[0])
	if err != nil {
		return fmt.Errorf("error opening the realm export: %w", err)
	}

	defer file.Close()

	return ctx.withManagementService(func(service *management.Service) (err error) {
		var report *management.KeycloakImportReport

		if report, err = service.ImportKeycloak(ctx.usersActor(), file, opts); err != nil {
			return err
		}

		writeKeycloakImportReport(cmd.OutOrStdout(), report)

		return nil
	})
}

func writeKeycloakImportReport(w io.Writer, report *management.KeycloakImportReport) {
	if report.Applied {
		_, _ = fmt.Fprintln(w, "Imported:")
	} else {
		_, _ = fmt.Fprintln(w, "Dry run, nothing was changed (import with --apply). It would import:")
	}

	count := func(counts map[string]int) string {
		parts := make([]string, 0, len(counts))

		for name, n := range counts {
			parts = append(parts, fmt.Sprintf("%s: %d", name, n))
		}

		sort.Strings(parts)

		return strings.Join(parts, ", ")
	}

	_, _ = fmt.Fprintf(w, "  users: %d (disabled: %d)\n  groups: %d\n  group memberships: %d\n  subject identifiers: %d\n  passwords: %s\n  WebAuthn credentials: %s\n",
		report.Users, report.Disabled, report.Groups, report.Memberships, report.Subjects, count(report.Passwords), count(report.WebAuthn))

	for _, list := range []struct {
		title string
		items []string
	}{{"Skipped", report.Skipped}, {"Warnings", report.Warnings}} {
		if len(list.items) == 0 {
			continue
		}

		_, _ = fmt.Fprintf(w, "%s:\n", list.title)

		for _, item := range list.items {
			_, _ = fmt.Fprintf(w, "  %s\n", item)
		}
	}
}

// usersImportCheckRPID refuses an RP ID which this configuration doesn't use: the host of an authelia_url, or a
// configured WebAuthn relying party. Imported passkeys only work for the RP ID they were registered for, and a wrong
// one would only show as passkeys which are never found. A configuration without either can't be checked.
func (ctx *CmdCtx) usersImportCheckRPID(rpid string) error {
	if rpid == "" {
		return nil
	}

	var known []string

	for _, cookie := range ctx.config.Session.Cookies {
		if cookie.AutheliaURL != nil {
			known = append(known, strings.ToLower(cookie.AutheliaURL.Hostname()))
		}
	}

	for id := range ctx.config.WebAuthn.RelyingParties {
		known = append(known, strings.ToLower(id))
	}

	if len(known) != 0 && !slices.Contains(known, strings.ToLower(rpid)) {
		sort.Strings(known)

		return fmt.Errorf("the WebAuthn RP ID '%s' is not one this configuration uses (%s)", rpid, strings.Join(known, ", "))
	}

	return nil
}
