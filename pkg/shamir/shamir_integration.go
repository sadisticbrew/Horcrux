package shamir

import (
	"encoding/base64"
	"fmt"
	"horcrux/pkg/envelope"
	"math/big"
)

func main() {
	fmt.Println("Starting key shatter and reconstruct process...")

	// 1. Get a random 32-byte key using your envelope code
	stream := &envelope.HorcruxStream{}
	stream.InitializeKey()
	originalSecret := stream.GetKey()

	// 2. Setup Shamir configuration
	threshold := 3
	totalShards := 5
	bits := 257 // Must be larger than the 256-bit key

	// 3. Split the secret into 5 shards
	sharer := NewShamirSharer(threshold, bits, originalSecret)
	encodedShards, encodedPrime, err := sharer.Generate(totalShards)
	if err != nil {
		fmt.Printf("Error: Failed to generate shards: %v\n", err)
		return
	}

	// 4. Decode the base64 Prime back into a *big.Int
	primeBytes, err := base64.StdEncoding.DecodeString(encodedPrime)
	if err != nil {
		fmt.Printf("Error: Failed to decode prime: %v\n", err)
		return
	}
	prime := new(big.Int).SetBytes(primeBytes)

	// 5. Select exactly 'threshold' (3) shards to test reconstruction
	selectedShards := make(map[int]*big.Int)
	count := 0
	for keyIndex, encodedValue := range encodedShards {
		if count >= threshold {
			break
		}

		shardBytes, err := base64.StdEncoding.DecodeString(encodedValue)
		if err != nil {
			fmt.Printf("Error: Failed to decode shard %d: %v\n", keyIndex, err)
			return
		}

		selectedShards[keyIndex] = new(big.Int).SetBytes(shardBytes)
		count++
	}

	// 6. Reconstruct the secret
	integrater := NewIntegrater(selectedShards, prime)
	reconstructedSecret := integrater.Integrate()

	// 7. Verify the reconstructed secret matches the original
	if originalSecret.Cmp(reconstructedSecret) == 0 {
		fmt.Println("SUCCESS: The key was shattered and reconstructed perfectly!")
	} else {
		fmt.Println("FAILURE: The reconstructed key does not match the original.")
		fmt.Printf("Original:      %x\n", originalSecret)
		fmt.Printf("Reconstructed: %x\n", reconstructedSecret)
	}
}
