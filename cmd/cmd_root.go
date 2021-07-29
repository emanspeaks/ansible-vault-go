package cmd

import (
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"

	"github.com/juju/loggo"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh/terminal"
)

type rootPFlagsStruct struct {
	Password          string
	passwordFlagValue string
	verbose           bool
	vaultPasswordFile string
}

var (
	// This two variables are set at build time
	Version   string
	BuildTime string

	// Logger
	out = loggo.GetLogger("cmd")

	// RootPFlags common flags
	RootPFlags = &rootPFlagsStruct{}

	// Command
	rootCmd = &cobra.Command{
		Use:           "ansible-vault-go",
		Short:         "Golang port of ansible-vault that can perform basic functions",
		Version:       fmt.Sprintf("%s (Built on: %s)", Version, BuildTime),
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			//goland:noinspection GoUnhandledErrorResult
			rootLogger := loggo.GetLogger("")

			if RootPFlags.verbose {
				rootLogger.SetLogLevel(loggo.DEBUG)
			} else {
				rootLogger.SetLogLevel(loggo.INFO)
			}

			topLevelCmd := cmd
			for {
				if !topLevelCmd.HasParent() {
					break
				}

				topLevelCmd = topLevelCmd.Parent()
			}

			out.Debugf("%s (Built on: %s)", Version, BuildTime)

			if RootPFlags.passwordFlagValue != "" && RootPFlags.vaultPasswordFile != "" {
				return fmt.Errorf("vault-password-file and password parameters are mutually exclusive")
			}
			if RootPFlags.passwordFlagValue != "" {
				RootPFlags.Password = RootPFlags.passwordFlagValue
			}
			if RootPFlags.vaultPasswordFile != "" {
				bytePassword, err := ioutil.ReadFile(RootPFlags.vaultPasswordFile)
				if err != nil {
					return err
				}
				// Fix line endings to match ansible-vault behavior
				RootPFlags.Password = strings.TrimRight(strings.TrimRight(string(bytePassword), "\r\n"), "\n")
			}
			if RootPFlags.Password == "" {
				out.Debugf("Password not set by flags. Prompting")
				//noinspection GoUnhandledErrorResult
				fmt.Fprint(os.Stderr, "New Vault password: ")
				bytePassword, err := terminal.ReadPassword(int(syscall.Stdin))
				fmt.Println()
				if err != nil {
					return err
				}
				RootPFlags.Password = string(bytePassword)
			}
			out.Debugf("Vault Password used (between []): [%s]", RootPFlags.Password)
			return nil
		},
	}
)

//goland:noinspection GoUnhandledErrorResult
func init() {
	rootCmd.PersistentFlags().
		BoolVarP(&RootPFlags.verbose, "verbose", "v", false, "enable verbose output. May print sensible information")
	rootCmd.PersistentFlags().
		StringVarP(&RootPFlags.passwordFlagValue, "password", "p", "", "ansible-vault password to use")
	rootCmd.PersistentFlags().
		StringVar(&RootPFlags.vaultPasswordFile, "vault-password-file", "", "file to read the vault password from (trim end of line)")
}

//Execute execute the command
func Execute() {
	//goland:noinspection GoUnhandledErrorResult
	err := rootCmd.Execute()

	if err != nil {
		if RootPFlags.verbose {
			out.Errorf("%v", err)
		} else {
			out.Errorf("%s", err.Error())
		}
	}
}
