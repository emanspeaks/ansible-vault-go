package cmd

import (
	"fmt"
	"os"

	"github.com/emanspeaks/avault/vault"
	"github.com/spf13/cobra"
)

type fileDecryptFlagsStruct struct {
	file     string
	output   string
	password string
}

var (
	fileDecryptFlags = &fileDecryptFlagsStruct{}

	fileDecryptCmd = &cobra.Command{
		Use:                   "decrypt [flags] [file]",
		Short:                 "Decrypt a file.",
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
	fileDecryptCmd.Flags().
		StringVar(&fileDecryptFlags.output, "output", "",
			"write decrypted output to this file instead of overwriting the input")
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
	if password == "" {
		return fmt.Errorf("no password provided for decryption")
	}

	plaintext, err := vault.Decrypt(content, password)
	if err != nil {
		return err
	}

	outPath := flags.file
	if flags.output != "" {
		outPath = flags.output
	}

	f, err := os.Create(outPath)
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

	// No label match: don't return a password and return an error.
	return "", fmt.Errorf("no vault-id matching content's vault ID %q", vaultID)
}
