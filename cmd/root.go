package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "horcrux [command] [files]",
	Short: "Horcrux is a cryptographic tool that securely splits sensitive data into multiple pieces.",
	Long:  "Horcrux secures your files using AES-256-GCM encryption, and then uses Shamir's Secret Sharing (SSS) to split the master encryption key into multiple distinct shards. You specify a 'threshold', the minimum number of shards required to rebuild the key and decrypt the file. If an attacker gets fewer shards than the threshold, they learn absolutely nothing about your key or your data.",
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
