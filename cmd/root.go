package cmd

import (
	"github.com/spf13/cobra"
	"os"
)

var rootCmd = &cobra.Command{
	Use:   "encryptor",
	Short: "AES-GCM encryption tool",
	Long: `AES-GCM encryption and decryption tool.

Usage:
  Encrypt: encryptor enc <plaintext> --key <key> --iv <iv>
  Decrypt: encryptor dec <ciphertext> --key <key> --iv <iv>`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Add persistent flags here if needed
}
