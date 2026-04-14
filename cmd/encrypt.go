package cmd

import (
	"encoding/json"
	"fmt"
	"horcrux/pkg/envelope"
	"horcrux/pkg/shamir"
	"os"
	"strconv"

	"github.com/spf13/cobra"
)

var shardsNo, threshold int

type shard struct {
	Prime string
	X     int
	Y     string
}

var encryptCmd = &cobra.Command{
	Use:   "encrypt [file to encrypt]",
	Short: "Encrypt a file and shatter the key",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if threshold > shardsNo {
			return fmt.Errorf("threshold must be less than or equal to shards")
		}
		fmt.Println("Encrytion called on file", args[0])
		lock(args)
		fmt.Printf("\nSuccess: %d Shards generated.\n\nWARNING: Move these shards to separate, secure locations (USB drives, password managers) and delete the local copies.", shardsNo)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().IntVarP(&shardsNo, "shards", "s", 5, "Number of shards to create")
	encryptCmd.Flags().IntVarP(&threshold, "threshold", "t", 3, "Threshold number of shards required to unlock")
}

func lock(args []string) error {
	s := envelope.NewHorcruxStream(args[0])
	err := s.InitializeKey()
	if err != nil {
		return err
	}
	var sec envelope.CipherStream = s

	err = sec.Encrypt()
	if err != nil {
		return err
	}

	var sharer shamir.SecretSplitter = shamir.NewShamirSharer(threshold, 512, s.GetKey())
	shards, prime, err := sharer.Generate(shardsNo)
	if err != nil {
		return err
	}
	err = generateShardFiles(shards, prime, args)
	if err != nil {
		return err
	}

	fmt.Println("Shards:", shards, "Prime:", prime)

	s.ClearKey()
	return nil
}

func generateShardFiles(shards map[int]string, prime string, args []string) error {

	for k, v := range shards {

		f, err := os.Create(args[0] + ".shard" + strconv.Itoa(k))
		if err != nil {
			return err
		}
		shard := shard{Prime: prime, X: k, Y: v}
		data, err := json.Marshal(shard)
		if err != nil {
			return err
		}

		_, err = f.Write(data)
		if err != nil {
			return err
		}

		f.Close()

	}
	return nil
}
