package shamir_test

import (
	"encoding/base64"
	"fmt"
	"horcrux/pkg/shamir"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"
)

type TestData struct {
	threshold      int
	totalShards    int
	bits           int
	originalSecret *big.Int
}

func TestGenerateThenIntegrate(t *testing.T) {
	// var ss shamir.SecretSplitter = shamir.NewShamirSharer()

	secret := new(big.Int).SetBytes([]byte("SecretData"))
	testCases := []TestData{{3, 5, 256, secret}, {3, 2, 256, secret}}

	for _, testCase := range testCases {
		t.Run(fmt.Sprintf("Threshold_%d_Shards_%d", testCase.threshold, testCase.totalShards), func(t *testing.T) {
			var ss shamir.SecretSplitter = shamir.NewShamirSharer(testCase.threshold, testCase.bits, testCase.originalSecret)

			shards, prime, err := ss.Generate(testCase.totalShards)
			require.NoError(t, err)
			require.Len(t, shards, testCase.totalShards)

			primeBytes, err := base64.StdEncoding.DecodeString(prime)
			require.NoError(t, err)

			primeInt := new(big.Int).SetBytes(primeBytes)

			newShards := make(map[int]*big.Int)
			for k, v := range shards {
				yValueBytes, err := base64.StdEncoding.DecodeString(v)
				require.NoError(t, err)
				yValueInt := new(big.Int).SetBytes(yValueBytes)

				newShards[k] = yValueInt
			}

			var integrater shamir.SecretIntegrater = shamir.NewIntegrater(newShards, primeInt)
			integratedSecret := integrater.Integrate()

			if testCase.threshold <= testCase.totalShards {
				require.Equal(t, 0, integratedSecret.Cmp(secret))
			} else if testCase.threshold > testCase.totalShards {
				require.NotEqual(t, 0, integratedSecret.Cmp(secret))
			}
		})

	}

}
