package cmd

import (
	"crypto/rand"
	"fmt"
	"os"

	"github.com/emanspeaks/avault/vault"
	"github.com/spf13/cobra"
)

type fileEncryptFlagsStruct struct {
	file           string
	output         string
	password       string
	encryptVaultID string
	salt           string
	force          bool
}

type randomTextEncryptFlagsStruct struct {
	password string
	length   int
}

var (
	fileEncryptFlags       = &fileEncryptFlagsStruct{}
	randomTextEncryptFlags = &randomTextEncryptFlagsStruct{}

	fileEncryptCmd = &cobra.Command{
		Use:                   "encrypt [flags] [file]",
		Short:                 "Encrypt a file.",
		DisableFlagsInUseLine: true,
		Args:                  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCmd.SilenceUsage = true
			fileEncryptFlags.password = RootPFlags.Password
			fileEncryptFlags.file = args[0]
			return doEncryptFile(fileEncryptFlags)
		},
	}

	randomTextEncryptCmd = &cobra.Command{
		Use:   "random_text_encrypt [flags]",
		Short: "Generate random text and encrypt it.",
		Long: `Generate random alphanumeric text and encrypt it.

Length is controlled by --length (default 32).`,
		DisableFlagsInUseLine: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			rootCmd.SilenceUsage = true
			randomTextEncryptFlags.password = RootPFlags.Password
			return doRandomTextEncrypt(randomTextEncryptFlags)
		},
	}
)

func init() {
	rootCmd.AddCommand(fileEncryptCmd)
	rootCmd.AddCommand(randomTextEncryptCmd)

	fileEncryptCmd.Flags().
		StringVar(&fileEncryptFlags.encryptVaultID, "encrypt-vault-id", "",
			"vault identity label to use for encryption (must match a --vault-id label)")
	fileEncryptCmd.Flags().
		StringVar(&fileEncryptFlags.output, "output", "",
			"write encrypted output to this file instead of overwriting the input")
	fileEncryptCmd.Flags().
		StringVar(&fileEncryptFlags.salt, "salt", "",
			"fixed salt for deterministic encryption (same salt+password+plaintext always produces identical output)")
	fileEncryptCmd.Flags().
		BoolVar(&fileEncryptFlags.force, "force", false,
			"always re-encrypt, skipping the idempotency check against the existing output file")

	randomTextEncryptCmd.Flags().
		IntVarP(&randomTextEncryptFlags.length, "length", "l", 32, "length of generated random text")
}

func doEncryptFile(flags *fileEncryptFlagsStruct) error {
	data, err := os.ReadFile(flags.file)
	if err != nil {
		return err
	}

	label, password := resolveEncryptIdentity(flags.encryptVaultID, flags.password)

	outPath := flags.file
	if flags.output != "" {
		outPath = flags.output
	}

	if !flags.force {
		if existing, readErr := os.ReadFile(outPath); readErr == nil {
			existingContent := string(existing)
			if vault.IsEncrypted(existingContent) {
				if plaintext, ok := decryptForComparison(existingContent, password); ok {
					if plaintext == string(data) {
						out.Info("output already encrypted with matching content, skipping")
						return nil
					}
				}
			}
		}
	}

	var salt []byte
	if flags.salt != "" {
		salt = []byte(flags.salt)
	}

	var cipher string
	if salt != nil {
		cipher, err = vault.EncryptByteArrayWithIDAndSalt(data, password, label, salt)
	} else {
		cipher, err = vault.EncryptByteArrayWithID(data, password, label)
	}
	if err != nil {
		return err
	}

	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if _, err := f.WriteString(cipher); err != nil {
		return err
	}
	out.Info("Encryption successful")
	return nil
}

// decryptForComparison attempts to decrypt existingContent to compare against
// incoming plaintext. It uses the vault-id list to find the right password when
// the file carries a label, falling back to encryptPassword when there is no
// label or no matching identity.
func decryptForComparison(existingContent, encryptPassword string) (string, bool) {
	pw, err := resolveDecryptPassword(existingContent, encryptPassword)
	if err != nil || pw == "" {
		pw = encryptPassword
	}
	plaintext, err := vault.Decrypt(existingContent, pw)
	if err != nil {
		return "", false
	}
	return plaintext, true
}

func doRandomTextEncrypt(flags *randomTextEncryptFlagsStruct) error {
	data, err := randomString(flags.length)
	if err != nil {
		return err
	}
	out.Debug("generated random string", "value", data)

	cipher, err := vault.Encrypt(data, flags.password)
	if err != nil {
		return err
	}
	fmt.Println(cipher)
	return nil
}

// resolveEncryptIdentity returns the (vaultID label, password) to use for encryption.
// If encryptVaultID names a known identity it is preferred; otherwise the first
// available identity is used; falling back to the legacy global password (format 1.1).
func resolveEncryptIdentity(encryptVaultID, fallbackPassword string) (string, string) {
	if encryptVaultID != "" {
		for _, vid := range RootPFlags.VaultIDs {
			if vid.Label == encryptVaultID {
				return vid.Label, vid.Password
			}
		}
	}
	if len(RootPFlags.VaultIDs) > 0 {
		vid := RootPFlags.VaultIDs[0]
		return vid.Label, vid.Password
	}
	return "", fallbackPassword
}

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func randomString(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	for i, v := range b {
		b[i] = charset[int(v)%len(charset)]
	}
	return string(b), nil
}
