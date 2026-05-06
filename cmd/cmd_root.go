package cmd

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
	vaultIDListFile   string
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
			RootPFlags.VaultIDs = nil
			RootPFlags.Password = ""
			vids, err := resolveConfiguredVaultIDs(RootPFlags.vaultIDListFile, RootPFlags.vaultIDStrings)
			if err != nil {
				return err
			}
			RootPFlags.VaultIDs = vids

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

// resolveVaultID parses "label@source" and returns the resolved identity(ies).
// The source is always treated as a plain password file (or "prompt"); list
// files must be supplied via --vault-id-list, not via the source field here.
func resolveVaultID(vidStr string) ([]*vaultIdentity, error) {
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
		source = resolvePath(source)
		data, err := os.ReadFile(source)
		if err != nil {
			return nil, fmt.Errorf("reading vault-id %q source %q: %w", label, source, err)
		}

		password = strings.TrimRight(string(data), "\r\n")
	}

	return []*vaultIdentity{{Label: label, Password: password}}, nil
}

// resolveConfiguredVaultIDs merges identities from --vault-id-list and
// repeated --vault-id flags. Same-label --vault-id values override list-file
// entries; new labels are appended.
func resolveConfiguredVaultIDs(listFile string, vaultIDStrings []string) ([]*vaultIdentity, error) {
	var ids []*vaultIdentity

	if listFile != "" {
		loaded, err := loadVaultIDListFile(listFile)
		if err != nil {
			return nil, err
		}
		ids = append(ids, loaded...)
	}

	for _, vidStr := range vaultIDStrings {
		resolved, err := resolveVaultID(vidStr)
		if err != nil {
			return nil, err
		}
		for _, vid := range resolved {
			ids = upsertVaultIdentity(ids, vid)
		}
	}

	return ids, nil
}

func upsertVaultIdentity(ids []*vaultIdentity, vid *vaultIdentity) []*vaultIdentity {
	for i, existing := range ids {
		if existing.Label == vid.Label {
			ids[i] = vid
			return ids
		}
	}

	return append(ids, vid)
}

// loadVaultIDListFile reads a vault-id list file and resolves all identities in
// it. Each non-blank, non-comment line must be in "label@source" format.
// Relative source paths in the file are resolved relative to the directory of
// the list file itself.
func loadVaultIDListFile(path string) ([]*vaultIdentity, error) {
	path = resolvePath(path)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading vault-id-list %q: %w", path, err)
	}
	content := strings.TrimRight(string(data), "\r\n")
	lines := parseVaultIDList(content)
	if len(lines) == 0 {
		return nil, fmt.Errorf("vault-id-list %q contains no valid label@source entries", path)
	}
	dir := filepath.Dir(path)
	var ids []*vaultIdentity
	for _, line := range lines {
		parts := strings.SplitN(line, "@", 2)
		sourcePart := parts[1]
		if sourcePart != "prompt" && !filepath.IsAbs(sourcePart) {
			sourcePart = filepath.Join(dir, sourcePart)
		}
		resolvedLine := parts[0] + "@" + sourcePart
		vids, err := resolveVaultID(resolvedLine)
		if err != nil {
			return nil, err
		}
		ids = append(ids, vids...)
	}
	return ids, nil
}

// resolvePath normalizes a vault-id source path. On Windows it attempts to
// convert Unix-style paths (e.g. /c/Users/... or ~/...) via cygpath.
func resolvePath(p string) string {
	if runtime.GOOS != "windows" || !looksLikeUnixPath(p) {
		return p
	}

	if abs, err := filepath.Abs(p); err == nil && filepath.IsAbs(abs) {
		return abs
	}

	if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			p = filepath.Join(home, p[2:])
		}
	}

	cmd := exec.Command("cygpath", "-w", p)
	out, err := cmd.Output()
	if err == nil {
		result := strings.TrimSpace(string(out))
		if len(result) > 0 {
			return result
		}
	}

	return p
}

// looksLikeUnixPath reports whether p appears to be a Unix-style absolute path.
func looksLikeUnixPath(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~")
}

// parseVaultIDList checks if content contains lines in "label@source" format.
// Returns the parsed lines if at least one non-empty line matches, otherwise nil.
func parseVaultIDList(content string) []string {
	var result []string
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "@", 2)
		if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
			result = append(result, line)
		}
	}
	if len(result) > 0 {
		return result
	}
	return nil
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
	rootCmd.Flags().Bool("version", false, "version for avault")
	rootCmd.PersistentFlags().
		BoolVarP(&RootPFlags.verbose, "verbose", "v", false, "enable verbose output (may print sensitive information)")
	rootCmd.PersistentFlags().
		StringVarP(&RootPFlags.passwordFlagValue, "password", "p", "", "vault password")
	rootCmd.PersistentFlags().
		StringVar(&RootPFlags.vaultPasswordFile, "vault-password-file", "", "read vault password from file")
	rootCmd.PersistentFlags().
		StringArrayVar(&RootPFlags.vaultIDStrings, "vault-id", nil,
			"vault identity in label@source format (source = file path or 'prompt'); may be repeated")
	rootCmd.PersistentFlags().
		StringVar(&RootPFlags.vaultIDListFile, "vault-id-list", "",
			"path to a vault-id list file; each line must be in label@source format")
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
