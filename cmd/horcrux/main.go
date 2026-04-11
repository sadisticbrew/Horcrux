package main

import (
	"fmt"
	"horcrux/pkg/crypto"
	"horcrux/pkg/shamir"
)

func main() {

	filepath := "yourfilepathhere"
	s := crypto.NewStreamer(filepath)

	sharer := &shamir.ShamirSharer{
		Threshold: 3,
		Bits:      512,
		Secret:    s.GetKey(),
	}

	fmt.Println("Enter total number of shards to generate:")
	var totalShards int
	fmt.Scanf("%d", &totalShards)

	var splitter shamir.SecretSplitter = sharer

	shards, prime, err := splitter.Generate(totalShards)
	if err != nil {
		panic(err)
	}
	s.ClearKey()

	fmt.Println("Master Prime:", prime)
	fmt.Printf("\n--- Shards ---\n")
	for key, value := range shards {
		fmt.Printf("Shard %d: %v\n", key, value)
	}
	reduced_shards := shards
	delete(reduced_shards, 1)
	delete(reduced_shards, 3)

	integrater := &shamir.Integrater{
		Shards: reduced_shards,
		Prime:  prime,
	}
	var integrate shamir.SecretIntegrater = integrater
	integrated := integrate.Integrate()
	fmt.Println("-----------------------------------------------")
	key := make([]byte, 32)
	integrated.FillBytes(key)
	s.SetKey(key)

	fmt.Println("Encrypting...")
	s.Encrypt()

	fmt.Println("Decrypting...")
	s.Decrypt()

}
