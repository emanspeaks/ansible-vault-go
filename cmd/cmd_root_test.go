package cmd

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/emanspeaks/avault/vault"
	"github.com/stretchr/testify/require"
)

func TestResolveConfiguredVaultIDs_ListArgsOverrideAndExtend(t *testing.T) {
	tmp := t.TempDir()

	require.NoError(t, os.WriteFile(filepath.Join(tmp, "master.key"), []byte("master-from-list\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "become.key"), []byte("become-from-list\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "override-master.key"), []byte("master-from-arg\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "ci.key"), []byte("ci-from-arg\n"), 0o600))

	listPath := filepath.Join(tmp, "vault-ids.txt")
	listContent := "master@master.key\nbecome@become.key\n"
	require.NoError(t, os.WriteFile(listPath, []byte(listContent), 0o600))

	ids, err := resolveConfiguredVaultIDs(listPath, []string{
		"master@" + filepath.Join(tmp, "override-master.key"),
		"ci@" + filepath.Join(tmp, "ci.key"),
	})
	require.NoError(t, err)
	require.Len(t, ids, 3)

	require.Equal(t, "master", ids[0].Label)
	require.Equal(t, "master-from-arg", ids[0].Password)
	require.Equal(t, "become", ids[1].Label)
	require.Equal(t, "become-from-list", ids[1].Password)
	require.Equal(t, "ci", ids[2].Label)
	require.Equal(t, "ci-from-arg", ids[2].Password)
}

func TestResolveConfiguredVaultIDs_ListFileRelativePaths(t *testing.T) {
	tmp := t.TempDir()
	keysDir := filepath.Join(tmp, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "master.key"), []byte("master-secret\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "become.key"), []byte("become-secret\n"), 0o600))

	listDir := filepath.Join(tmp, "config")
	require.NoError(t, os.MkdirAll(listDir, 0o755))
	listPath := filepath.Join(listDir, "vault-ids.txt")
	listContent := "master@../keys/master.key\nbecome@../keys/become.key\n"
	require.NoError(t, os.WriteFile(listPath, []byte(listContent), 0o600))

	ids, err := resolveConfiguredVaultIDs(listPath, nil)
	require.NoError(t, err)
	require.Len(t, ids, 2)
	require.Equal(t, "master", ids[0].Label)
	require.Equal(t, "master-secret", ids[0].Password)
	require.Equal(t, "become", ids[1].Label)
	require.Equal(t, "become-secret", ids[1].Password)
}

func TestResolveVaultID_SourceFileIsNotTreatedAsList(t *testing.T) {
	tmp := t.TempDir()
	sourcePath := filepath.Join(tmp, "password.txt")
	require.NoError(t, os.WriteFile(sourcePath, []byte("not-a-list@all\n"), 0o600))

	ids, err := resolveVaultID("master@" + sourcePath)
	require.NoError(t, err)
	require.Len(t, ids, 1)
	require.Equal(t, "master", ids[0].Label)
	require.Equal(t, "not-a-list@all", ids[0].Password)
}

func TestDecryptCommand_VaultIDArgOverridesVaultIDList(t *testing.T) {
	resetRootFlagsForTest(t)

	tmp := t.TempDir()
	plaintext := "super secret\n"
	encrypted, err := vault.EncryptWithID(plaintext, "override-password", "master")
	require.NoError(t, err)

	encryptedPath := filepath.Join(tmp, "secret.vault")
	outputPath := filepath.Join(tmp, "secret.txt")
	listPath := filepath.Join(tmp, "vault-ids.txt")
	wrongPasswordPath := filepath.Join(tmp, "master-from-list.key")
	overridePasswordPath := filepath.Join(tmp, "master-from-arg.key")

	require.NoError(t, os.WriteFile(encryptedPath, []byte(encrypted), 0o600))
	require.NoError(t, os.WriteFile(wrongPasswordPath, []byte("wrong-password\n"), 0o600))
	require.NoError(t, os.WriteFile(overridePasswordPath, []byte("override-password\n"), 0o600))
	require.NoError(t, os.WriteFile(listPath, []byte("master@master-from-list.key\n"), 0o600))

	rootCmd.SetOut(io.Discard)
	rootCmd.SetErr(io.Discard)
	rootCmd.SetArgs([]string{
		"--vault-id-list", listPath,
		"--vault-id", "master@" + overridePasswordPath,
		"decrypt",
		"--output", outputPath,
		encryptedPath,
	})

	err = rootCmd.Execute()
	require.NoError(t, err)

	decrypted, err := os.ReadFile(outputPath)
	require.NoError(t, err)
	require.Equal(t, plaintext, string(decrypted))
	require.Equal(t, "override-password", RootPFlags.Password)
	require.Len(t, RootPFlags.VaultIDs, 1)
	require.Equal(t, "master", RootPFlags.VaultIDs[0].Label)
	require.Equal(t, "override-password", RootPFlags.VaultIDs[0].Password)
}

func resetRootFlagsForTest(t *testing.T) {
	t.Helper()

	RootPFlags.Password = ""
	RootPFlags.passwordFlagValue = ""
	RootPFlags.verbose = false
	RootPFlags.vaultPasswordFile = ""
	RootPFlags.vaultIDStrings = nil
	RootPFlags.vaultIDListFile = ""
	RootPFlags.VaultIDs = nil
	rootCmd.SilenceUsage = false

	t.Cleanup(func() {
		RootPFlags.Password = ""
		RootPFlags.passwordFlagValue = ""
		RootPFlags.verbose = false
		RootPFlags.vaultPasswordFile = ""
		RootPFlags.vaultIDStrings = nil
		RootPFlags.vaultIDListFile = ""
		RootPFlags.VaultIDs = nil
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(io.Discard)
		rootCmd.SetErr(io.Discard)
		rootCmd.SilenceUsage = false
	})
}
