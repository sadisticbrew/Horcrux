# Horcrux

A cryptographic secret sharing engine written in Go, built from scratch. 

Horcrux uses Shamir's Secret Sharing to split a secret (like a password or a cryptographic key) into multiple distinct shards. You can specify a "threshold"—the minimum number of shards required to piece the original secret back together. If an attacker gets fewer shards than the threshold, they learn absolutely nothing about the secret.

## Current State
The core mathematical engine is fully functional. It handles the finite field arithmetic, random prime generation, and Lagrange interpolation required to split and rebuild secrets safely.

**Current Features:**
* Custom Shamir's Secret Sharing implementation.
* Dynamic threshold and shard generation.
* Large integer math handling via Go's `math/big`.

**Planned Features:**
* [ ] Full Command Line Interface (CLI) using Cobra.
* [ ] Envelope encryption using AES-256-GCM.
* [ ] Support for file-based sharding using `io.Reader` and `io.Writer`.

## How to Run

Right now, the project contains a demonstration of the core engine in `main.go`. 

1. Ensure you have Go installed.
2. Clone the repository:
   ```bash
   git clone [https://github.com/yourusername/horcrux.git](https://github.com/yourusername/horcrux.git)
   cd horcrux
   go run main.go
   ```
