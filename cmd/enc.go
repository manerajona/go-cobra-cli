package cmd

import (
	"aes-cli/aesgcm"
	"fmt"
	"github.com/spf13/cobra"
)

// encCmd represents the enc command
var encCmd = &cobra.Command{
	Use:   "enc",
	Short: "Encrypt plaintext using AES-GCM",
	Long: `Encrypt plaintext using AES-GCM encryption.
Usage: enc --iv <iv> --key <key> <plaintext>`,
	Run: func(cmd *cobra.Command, args []string) {
		if len(args) < 1 {
			fmt.Println("Error: plaintext argument required")
			return
		}

		iv := cmd.Flag("iv").Value.String()
		key := cmd.Flag("key").Value.String()

		encryptor, err := aesgcm.NewEncryptor(key, iv)
		if err != nil {
			fmt.Println("Error creating encryptor:", err)
			return
		}

		ciphertext, err := encryptor.Encrypt(args[0])
		if err != nil {
			fmt.Println("Encryption error:", err)
			return
		}
		fmt.Println(ciphertext)
	},
}

func init() {
	rootCmd.AddCommand(encCmd)
	encCmd.Flags().String("iv", "", "IV for encryption")
	encCmd.Flags().String("key", "", "Key for encryption")
	encCmd.MarkFlagRequired("iv")
	encCmd.MarkFlagRequired("key")
}
