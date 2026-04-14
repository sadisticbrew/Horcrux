package cmd

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"horcrux/pkg/envelope"
	"horcrux/pkg/shamir"
	"io"
	"math/big"
	"os"
	"strings"

	"github.com/spf13/cobra"
)

var shards []string

type Shard struct {
	Prime string
	X     int
	Y     string
}

type DecodedShard struct {
	Prime *big.Int
	X     int
	Y     *big.Int
}

var decryptCmd = &cobra.Command{
	Use:   "decrypt [filename] -s [shard files]",
	Short: "",
	Args:  cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		if len(shards) == 0 {
			return fmt.Errorf("No shard files provided!")
		}
		fp := strings.TrimSuffix(args[0], ".enc")
		unlock(fp)
		return nil
		// readShardFiles(shards)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringSliceVarP(&shards, "shards", "s", []string{}, "Shard files")
}

func unlock(fp string) {
	readShards := readShardFiles(shards)

	shardMap, masterPrime := parseToMap(readShards)

	i := shamir.NewIntegrater(shardMap, masterPrime)
	var integrater shamir.SecretIntegrater = i

	key := integrater.Integrate()
	buff := make([]byte, 32)
	s := envelope.NewHorcruxStream(fp)
	s.SetKey(key.FillBytes(buff))
	var sec envelope.CipherStream = s

	sec.Decrypt()

}

func parseToMap(shards []DecodedShard) (map[int]*big.Int, *big.Int) {
	masterPrime := shards[0].Prime
	shardMap := make(map[int]*big.Int)

	for _, shard := range shards {
		if masterPrime.Cmp(shard.Prime) != 0 {
			panic("Master prime mismatch in the shards!")
		}
		shardMap[shard.X] = shard.Y
	}

	return shardMap, masterPrime
}

func readShardFiles(shards []string) []DecodedShard {
	var result []DecodedShard
	for _, s := range shards {
		f, err := os.Open(s)
		if err != nil {
			fmt.Println("Error occoured while opening shard file: ", s)
		}
		var shard Shard

		byteJsonValue, err := io.ReadAll(f)
		if err != nil {
			fmt.Println("Error occoured while reading shard file: ", s)
		}

		err = json.Unmarshal(byteJsonValue, &shard)
		result = append(result, decodeShard(shard))
		f.Close()
	}
	return result
}

func decodeShard(shard Shard) DecodedShard {
	var err error
	var newShard DecodedShard

	byteBigIntPrime, err := base64.StdEncoding.DecodeString(shard.Prime)
	newShard.Prime = new(big.Int).SetBytes(byteBigIntPrime)
	if err != nil {
		fmt.Println("Error occoured while decoding shard prime: ", err)
	}

	newShard.X = shard.X

	byteBigIntY, err := base64.StdEncoding.DecodeString(shard.Y)
	newShard.Y = new(big.Int).SetBytes(byteBigIntY)
	if err != nil {
		fmt.Println("Error occoured while decoding shard Y: ", err)
	}

	return newShard
}
