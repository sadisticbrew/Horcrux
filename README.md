# Horcrux

A cryptographic file encryption and secret sharing engine written in Go.

Horcrux secures your files using AES-256-GCM envelope encryption, and then uses Shamir's Secret Sharing (SSS) to split the master encryption key into multiple distinct shards. You specify a "threshold"—the minimum number of shards required to rebuild the key and decrypt the file. If an attacker gets fewer shards than the threshold, they learn absolutely nothing about your key or your data.

## Current State
The core backend engine is fully functional and production-ready. It features a memory-safe chunking protocol capable of encrypting and decrypting massive files (like gigabyte-sized backups) without consuming excessive RAM. The SSS math engine and the encryption tools are cleanly separated into reusable Go packages.

**Current Features:**
* Custom Shamir's Secret Sharing implementation built from scratch.
* Secure envelope encryption using AES-256-GCM.
* Memory-efficient file streaming (chunking protocol) for large files.
* Modular Go package architecture (`pkg/shamir` and `pkg/crypto`).

**Planned Features:**
* [ ] Full Command Line Interface (CLI) using the Cobra framework.
* [ ] OS Keyring integration for secure, persistent local key storage.

## How to Run

Right now, the project contains a demonstration of the full encryption, sharding, and decryption lifecycle in `main.go`. 

1. Ensure you have Go installed.
2. Clone the repository:
   ```bash
   git clone [https://github.com/prathampatel/horcrux.git](https://github.com/prathampatel/horcrux.git)
   cd horcrux
    ```
3. Set your filepath in cmd/horcrux/main.go file
4. Run the engine:
   ```bash
   go run cmd/horcrux/main.go
    ```
5. The program will generate a secure key, encrypt a target file, shatter the key into your specified number of shards, and then demonstrate successfully rebuilding the key to decrypt the file.
