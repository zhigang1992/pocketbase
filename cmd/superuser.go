package cmd

import (
	"errors"
	"fmt"
	"time"

	"github.com/fatih/color"
	"github.com/go-ozzo/ozzo-validation/v4/is"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/security"
	"github.com/spf13/cobra"
)

// NewSuperuserCommand creates and returns new command for managing
// superuser accounts (create, update, upsert, delete).
func NewSuperuserCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:   "superuser",
		Short: "Manage superusers",
	}

	command.AddCommand(superuserUpsertCommand(app))
	command.AddCommand(superuserCreateCommand(app))
	command.AddCommand(superuserUpdateCommand(app))
	command.AddCommand(superuserDeleteCommand(app))
	command.AddCommand(superuserOTPCommand(app))
	command.AddCommand(superuserImpersonateCommand(app))

	return command
}

func superuserUpsertCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:          "upsert",
		Example:      "superuser upsert test@example.com 1234567890",
		Short:        "Creates, or updates if email exists, a single superuser",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("missing email and password arguments")
			}

			if args[0] == "" || is.EmailFormat.Validate(args[0]) != nil {
				return errors.New("missing or invalid email address")
			}

			superusersCol, err := app.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
			if err != nil {
				return fmt.Errorf("failed to fetch %q collection: %w", core.CollectionNameSuperusers, err)
			}

			superuser, err := app.FindAuthRecordByEmail(superusersCol, args[0])
			if err != nil {
				superuser = core.NewRecord(superusersCol)
			}

			superuser.SetEmail(args[0])
			superuser.SetPassword(args[1])

			if err := app.Save(superuser); err != nil {
				return fmt.Errorf("failed to upsert superuser account: %w", err)
			}

			color.Green("Successfully saved superuser %q!", superuser.Email())
			return nil
		},
	}

	return command
}

func superuserCreateCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:          "create",
		Example:      "superuser create test@example.com 1234567890",
		Short:        "Creates a new superuser",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("missing email and password arguments")
			}

			if args[0] == "" || is.EmailFormat.Validate(args[0]) != nil {
				return errors.New("missing or invalid email address")
			}

			superusersCol, err := app.FindCachedCollectionByNameOrId(core.CollectionNameSuperusers)
			if err != nil {
				return fmt.Errorf("failed to fetch %q collection: %w", core.CollectionNameSuperusers, err)
			}

			superuser := core.NewRecord(superusersCol)
			superuser.SetEmail(args[0])
			superuser.SetPassword(args[1])

			if err := app.Save(superuser); err != nil {
				return fmt.Errorf("failed to create new superuser account: %w", err)
			}

			color.Green("Successfully created new superuser %q!", superuser.Email())
			return nil
		},
	}

	return command
}

func superuserUpdateCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:          "update",
		Example:      "superuser update test@example.com 1234567890",
		Short:        "Changes the password of a single superuser",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) != 2 {
				return errors.New("missing email and password arguments")
			}

			if args[0] == "" || is.EmailFormat.Validate(args[0]) != nil {
				return errors.New("missing or invalid email address")
			}

			superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, args[0])
			if err != nil {
				return fmt.Errorf("superuser with email %q doesn't exist", args[0])
			}

			superuser.SetPassword(args[1])

			if err := app.Save(superuser); err != nil {
				return fmt.Errorf("failed to change superuser %q password: %w", superuser.Email(), err)
			}

			color.Green("Successfully changed superuser %q password!", superuser.Email())
			return nil
		},
	}

	return command
}

func superuserDeleteCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:          "delete",
		Example:      "superuser delete test@example.com",
		Short:        "Deletes an existing superuser",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "" || is.EmailFormat.Validate(args[0]) != nil {
				return errors.New("invalid or missing email address")
			}

			superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, args[0])
			if err != nil {
				color.Yellow("superuser %q is missing or already deleted", args[0])
				return nil
			}

			if err := app.Delete(superuser); err != nil {
				return fmt.Errorf("failed to delete superuser %q: %w", superuser.Email(), err)
			}

			color.Green("Successfully deleted superuser %q!", superuser.Email())
			return nil
		},
	}

	return command
}

func superuserOTPCommand(app core.App) *cobra.Command {
	command := &cobra.Command{
		Use:          "otp",
		Example:      "superuser otp test@example.com",
		Short:        "Creates a new OTP for the specified superuser",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "" || is.EmailFormat.Validate(args[0]) != nil {
				return errors.New("invalid or missing email address")
			}

			superuser, err := app.FindAuthRecordByEmail(core.CollectionNameSuperusers, args[0])
			if err != nil {
				return fmt.Errorf("superuser with email %q doesn't exist", args[0])
			}

			if !superuser.Collection().OTP.Enabled {
				return errors.New("OTP auth is not enabled for the _superusers collection")
			}

			pass := security.RandomStringWithAlphabet(superuser.Collection().OTP.Length, "1234567890")

			otp := core.NewOTP(app)
			otp.SetCollectionRef(superuser.Collection().Id)
			otp.SetRecordRef(superuser.Id)
			otp.SetPassword(pass)

			err = app.Save(otp)
			if err != nil {
				return fmt.Errorf("failed to create OTP: %w", err)
			}

			color.New(color.BgGreen, color.FgBlack).Printf("Successfully created OTP for superuser %q:", superuser.Email())
			color.Green("\n├─ Id:    %s", otp.Id)
			color.Green("├─ Pass:  %s", pass)
			color.Green("└─ Valid: %ds\n\n", superuser.Collection().OTP.Duration)
			return nil
		},
	}

	return command
}

func superuserImpersonateCommand(app core.App) *cobra.Command {
	var durationFlag int64

	command := &cobra.Command{
		Use:          "impersonate",
		Example:      "superuser impersonate users user@example.com\nsuperuser impersonate users user@example.com --duration 3600",
		Short:        "Generates an impersonation auth token for a user in an auth collection",
		SilenceUsage: true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) < 2 {
				return errors.New("missing collection and user identifier arguments")
			}

			collectionArg := args[0]
			userIdentifier := args[1]

			collection, err := app.FindCachedCollectionByNameOrId(collectionArg)
			if err != nil {
				return fmt.Errorf("failed to find collection %q: %w", collectionArg, err)
			}

			if !collection.IsAuth() {
				return fmt.Errorf("collection %q is not an auth collection", collectionArg)
			}

			// Try to find user by email first, then by ID
			var record *core.Record
			if is.EmailFormat.Validate(userIdentifier) == nil {
				record, err = app.FindAuthRecordByEmail(collection, userIdentifier)
			} else {
				record, err = app.FindRecordById(collection, userIdentifier)
			}

			if err != nil {
				return fmt.Errorf("failed to find user %q in collection %q: %w", userIdentifier, collectionArg, err)
			}

			duration := time.Duration(durationFlag) * time.Second

			token, err := record.NewStaticAuthToken(duration)
			if err != nil {
				return fmt.Errorf("failed to generate impersonation token: %w", err)
			}

			color.New(color.BgGreen, color.FgBlack).Printf("Successfully generated impersonation token for %q:", record.Email())
			color.Green("\n├─ Collection: %s", collection.Name)
			color.Green("├─ Record ID:  %s", record.Id)
			color.Green("├─ Email:      %s", record.Email())
			if durationFlag > 0 {
				color.Green("├─ Duration:   %ds", durationFlag)
			} else {
				color.Green("├─ Duration:   %ds (collection default)", collection.AuthToken.Duration)
			}
			color.Green("└─ Token:      %s\n\n", token)
			return nil
		},
	}

	command.Flags().Int64VarP(&durationFlag, "duration", "d", 0, "Custom token duration in seconds (0 = collection default)")

	return command
}
