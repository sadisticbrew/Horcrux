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
		err := unlock(fp)
		if err != nil {
			return err
		}
		return nil
		// readShardFiles(shards)
	},
}

func init() {
	rootCmd.AddCommand(decryptCmd)
	decryptCmd.Flags().StringSliceVarP(&shards, "shards", "s", []string{}, "Shard files")
}

func unlock(fp string) error {
	readShards, err := readShardFiles(shards)
	if err != nil {
		return err
	}

	shardMap, masterPrime, err := parseToMap(readShards)
	if err != nil {
		return err
	}

	i := shamir.NewIntegrater(shardMap, masterPrime)
	var integrater shamir.SecretIntegrater = i

	key := integrater.Integrate()
	buff := make([]byte, 32)
	s := envelope.NewHorcruxStream(fp)
	s.SetKey(key.FillBytes(buff))
	var sec envelope.CipherStream = s

	err = sec.Decrypt()
	if err != nil {
		return err
	}
	return nil

}

func parseToMap(shards []DecodedShard) (map[int]*big.Int, *big.Int, error) {
	masterPrime := shards[0].Prime
	shardMap := make(map[int]*big.Int)

	for _, shard := range shards {
		if masterPrime.Cmp(shard.Prime) != 0 {
			return nil, nil, fmt.Errorf("Master prime mismatch in the shards!")
		}
		shardMap[shard.X] = shard.Y
	}

	return shardMap, masterPrime, nil
}

func readShardFiles(shards []string) ([]DecodedShard, error) {
	var result []DecodedShard
	for _, s := range shards {
		f, err := os.Open(s)
		if err != nil {
			return nil, fmt.Errorf("Error while opening shard file: %v", err)
		}
		var shard Shard

		byteJsonValue, err := io.ReadAll(f)
		if err != nil {
			f.Close()

			return nil, fmt.Errorf("Error while reading a shard: %v", err)
		}

		err = json.Unmarshal(byteJsonValue, &shard)
		if err != nil {
			f.Close()

			return nil, err
		}

		decodedShard, err := decodeShard(shard)
		if err != nil {
			f.Close()
			return nil, err
		}

		result = append(result, decodedShard)
		f.Close()
	}
	return result, nil
}

func decodeShard(shard Shard) (DecodedShard, error) {
	var newShard DecodedShard

	byteBigIntPrime, err := base64.StdEncoding.DecodeString(shard.Prime)
	if err != nil {
		return DecodedShard{}, err
	}

	newShard.Prime = new(big.Int).SetBytes(byteBigIntPrime)

	newShard.X = shard.X

	byteBigIntY, err := base64.StdEncoding.DecodeString(shard.Y)
	if err != nil {
		return DecodedShard{}, err
	}
	newShard.Y = new(big.Int).SetBytes(byteBigIntY)

	return newShard, nil
}
