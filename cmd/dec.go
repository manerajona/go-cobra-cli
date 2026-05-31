package cmd

import (
	"aes-cli/aesgcm"
	"fmt"

	"github.com/spf13/cobra"
)

// decCmd represents the dec command
var decCmd = &cobra.Command{
	Use:   "dec",
	Short: "Decrypt ciphertext using AES-GCM",
	Long: `Decrypt ciphertext using AES-GCM encryption.
Usage: dec <ciphertext> --iv <iv> --key <key>`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Error: ciphertext argument required")
			return
		}

		iv := cmd.Flag("iv").Value.String()
		key := cmd.Flag("key").Value.String()

		encryptor, err := aesgcm.NewEncryptor(key, iv)
		if err != nil {
			fmt.Println("Error creating encryptor:", err)
			return
		}

		plaintext, err := encryptor.Decrypt(args[0])
		if err != nil {
			fmt.Println("Decryption error:", err)
			return
		}
		fmt.Println(plaintext)
	},
}

func init() {
	rootCmd.AddCommand(decCmd)
	decCmd.Flags().String("iv", "", "IV for encryption")
	decCmd.Flags().String("key", "", "Key for encryption")
	decCmd.MarkFlagRequired("iv")
	decCmd.MarkFlagRequired("key")
}
