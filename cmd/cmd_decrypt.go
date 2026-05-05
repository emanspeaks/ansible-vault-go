package cmd

import (
	"os"

	"github.com/emanspeaks/ansible-vault-go/vault"
	"github.com/spf13/cobra"
)

type fileDecryptFlagsStruct struct {
	file     string
	password string
}

var (
	fileDecryptFlags = &fileDecryptFlagsStruct{}

	fileDecryptCmd = &cobra.Command{
		Use:                   "decrypt [flags] [file]",
		Short:                 "Decrypt a file in place.",
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCmd.SilenceUsage = true
			fileDecryptFlags.file = args[0]
			fileDecryptFlags.password = RootPFlags.Password
			return doDecryptFile(fileDecryptFlags)
		},
	}
)

func init() {
	rootCmd.AddCommand(fileDecryptCmd)
}

func doDecryptFile(flags *fileDecryptFlagsStruct) error {
	data, err := os.ReadFile(flags.file)
	if err != nil {
		return err
	}

	content := string(data)
	password, err := resolveDecryptPassword(content, flags.password)
	if err != nil {
		return err
	}

	plaintext, err := vault.Decrypt(content, password)
	if err != nil {
		return err
	}

	f, err := os.Create(flags.file)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(plaintext); err != nil {
		return err
	}
	out.Info("Decryption successful")
	return nil
}

// resolveDecryptPassword picks the right password for content by matching the
// vault ID in its header against the registered --vault-id identities.
// Falls back to fallback (the global password) when no vault IDs are configured
// or when no label matches.
func resolveDecryptPassword(content, fallback string) (string, error) {
	if len(RootPFlags.VaultIDs) == 0 {
		return fallback, nil
	}

	vaultID, err := vault.ReadVaultID(content)
	if err != nil {
		return "", err
	}

	// Prefer the identity whose label matches the header.
	for _, vid := range RootPFlags.VaultIDs {
		if vid.Label == vaultID {
			return vid.Password, nil
		}
	}

	// No label match: use the first available identity (handles 1.1 format or
	// files where the label wasn't passed on the command line).
	return RootPFlags.VaultIDs[0].Password, nil
}
