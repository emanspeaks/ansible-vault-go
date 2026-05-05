package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type vaultIdentity struct {
	Label    string
	Password string
}

type rootPFlagsStruct struct {
	Password          string
	passwordFlagValue string
	verbose           bool
	vaultPasswordFile string
	vaultIDStrings    []string
	VaultIDs          []*vaultIdentity
}

var (
	// Version and BuildTime are set at build time via -ldflags.
	Version   string
	BuildTime string

	logLevel = new(slog.LevelVar)
	out      = slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: logLevel}))

	// RootPFlags holds common flags resolved for every command.
	RootPFlags = &rootPFlagsStruct{}

	rootCmd = &cobra.Command{
		Use:           "avault",
		Short:         "Golang implementation of ansible-vault encryption/decryption",
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if RootPFlags.verbose {
				logLevel.Set(slog.LevelDebug)
			}

			out.Debug("build info", "version", Version, "buildTime", BuildTime)

			// Resolve vault IDs.
			for _, vidStr := range RootPFlags.vaultIDStrings {
				vid, err := resolveVaultID(vidStr)
				if err != nil {
					return err
				}
				RootPFlags.VaultIDs = append(RootPFlags.VaultIDs, vid)
			}

			if RootPFlags.passwordFlagValue != "" && RootPFlags.vaultPasswordFile != "" {
				return fmt.Errorf("--vault-password-file and --password are mutually exclusive")
			}

			switch {
			case RootPFlags.passwordFlagValue != "":
				RootPFlags.Password = RootPFlags.passwordFlagValue
			case RootPFlags.vaultPasswordFile != "":
				data, err := os.ReadFile(RootPFlags.vaultPasswordFile)
				if err != nil {
					return err
				}
				RootPFlags.Password = strings.TrimRight(string(data), "\r\n")
			case len(RootPFlags.VaultIDs) == 0:
				// No vault IDs and no explicit password — prompt interactively.
				fmt.Fprint(os.Stderr, "Vault password: ")
				raw, err := term.ReadPassword(int(syscall.Stdin))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return err
				}
				RootPFlags.Password = string(raw)
			}

			// When vault IDs are the sole password source, use the first one as the
			// default for commands that haven't been updated to pick a specific identity.
			if RootPFlags.Password == "" && len(RootPFlags.VaultIDs) > 0 {
				RootPFlags.Password = RootPFlags.VaultIDs[0].Password
			}

			out.Debug("vault configuration ready", "identities", len(RootPFlags.VaultIDs))
			return nil
		},
	}
)

// resolveVaultID parses "label@source" and returns the resolved identity.
// source may be a file path or the literal string "prompt".
func resolveVaultID(vidStr string) (*vaultIdentity, error) {
	parts := strings.SplitN(vidStr, "@", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil, fmt.Errorf("--vault-id %q must be in label@source format (source is a file path or 'prompt')", vidStr)
	}
	label, source := parts[0], parts[1]

	var password string
	if source == "prompt" {
		fmt.Fprintf(os.Stderr, "Vault password (%s): ", label)
		raw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			return nil, fmt.Errorf("reading vault-id %q password: %w", label, err)
		}
		password = string(raw)
	} else {
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("reading vault-id %q source %q: %w", label, source, err)
		}
		password = strings.TrimRight(string(data), "\r\n")
	}

	return &vaultIdentity{Label: label, Password: password}, nil
}

func formatVersion(ver, buildTime string) string {
	if ver == "" {
		ver = "dev"
	}
	if buildTime == "" {
		return ver
	}
	return ver + " (built: " + buildTime + ")"
}

func init() {
	// Pre-declare --version without a shorthand so cobra doesn't claim -v,
	// which is already used by --verbose.
	rootCmd.Flags().Bool("version", false, "version for ansible-vault-go")
	rootCmd.PersistentFlags().
		BoolVarP(&RootPFlags.verbose, "verbose", "v", false, "enable verbose output (may print sensitive information)")
	rootCmd.PersistentFlags().
		StringVarP(&RootPFlags.passwordFlagValue, "password", "p", "", "vault password")
	rootCmd.PersistentFlags().
		StringVar(&RootPFlags.vaultPasswordFile, "vault-password-file", "", "read vault password from file")
	rootCmd.PersistentFlags().
		StringArrayVar(&RootPFlags.vaultIDStrings, "vault-id", nil,
			"vault identity in label@source format (source = file path or 'prompt'); may be repeated")
}

// Execute runs the root command.
func Execute() {
	ver := formatVersion(Version, BuildTime)
	rootCmd.Version = ver
	rootCmd.Long = "avault " + ver + "\n\n" + rootCmd.Short
	rootCmd.SetVersionTemplate("avault {{.Version}}\n")
	if err := rootCmd.Execute(); err != nil {
		if RootPFlags.verbose {
			out.Error("command failed", "err", err)
		} else {
			out.Error(err.Error())
		}
	}
}
