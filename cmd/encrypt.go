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
		fmt.Printf("Success: %d Shards generated.\n\nWARNING: Move these shards to separate, secure locations (USB drives, password managers) and delete the local copies.", shardsNo)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(encryptCmd)
	encryptCmd.Flags().IntVarP(&shardsNo, "shards", "s", 5, "Number of shards to create")
	encryptCmd.Flags().IntVarP(&threshold, "threshold", "t", 3, "Threshold number of shards required to unlock")
}

func lock(args []string) {
	s := envelope.NewHorcruxStream(args[0])
	s.InitializeKey()
	var sec envelope.CipherStream = s
	err := sec.Encrypt()
	if err != nil {
		fmt.Println(err)
	}
	var sharer shamir.SecretSplitter = shamir.NewShamirSharer(threshold, 512, s.GetKey())
	shards, prime, err := sharer.Generate(shardsNo)
	generateShardFiles(shards, prime, args)
	if err != nil {
		fmt.Println(err)
	}

	fmt.Println("Shards:", shards, "Prime:", prime)

	s.ClearKey()
}

func generateShardFiles(shards map[int]string, prime string, args []string) {

	for k, v := range shards {

		f, _ := os.Create(args[0] + ".shard" + strconv.Itoa(k))

		shard := shard{Prime: prime, X: k, Y: v}
		data, _ := json.Marshal(shard)

		_, err := f.Write(data)
		if err != nil {
			panic(err)
		}

		f.Close()

	}
}
