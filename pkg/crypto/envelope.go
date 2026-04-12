package crypto

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
)

type LockUnlockFile interface {
	Encrypt() error
	Decrypt()
}

type Streamer struct {
	Filepath string
	key      []byte
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (s *Streamer) init() error {
	s.key = make([]byte, 32)
	_, err := rand.Read(s.key)
	if err != nil {
		return fmt.Errorf("Error generating the key: %w", err)
	}
	return nil
}

func (s *Streamer) GetKey() *big.Int {
	fmt.Println("original key: ", s.key)
	return new(big.Int).SetBytes(s.key)
}
func (s *Streamer) ClearKey() {
	s.key = nil
}
func (s *Streamer) SetKey(key []byte) {
	s.key = key
}

func (s *Streamer) Encrypt() error {

	f, _ := os.Open(s.Filepath)
	defer f.Close()
	r, _ := os.Create(s.Filepath + ".enc")
	defer r.Close()

	block, err := aes.NewCipher(s.key)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)

	reader := bufio.NewReader(f)
	buff := make([]byte, 4096)

	for {
		n, err := reader.Read(buff)
		if n < len(buff) {
			fmt.Println("read bytes less than the buff", n)
		}
		if err == io.EOF {
			break
		}
		check(err)

		r.Write(encrypt(buff[:n], gcm))
	}

	return nil
}
func (s *Streamer) Decrypt() {
	f, _ := os.Open(s.Filepath + ".enc")
	defer f.Close()
	r, _ := os.Create(s.Filepath + ".dec")
	defer r.Close()

	block, err := aes.NewCipher(s.key)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)

	nonceSize := gcm.NonceSize()
	targetReadSize := 4096 + nonceSize + gcm.Overhead()
	reader := bufio.NewReaderSize(f, targetReadSize)

	buff := make([]byte, targetReadSize)

	for {
		n, err := io.ReadFull(reader, buff)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			r.Write(decrypt(buff[:n], nonceSize, gcm))
			break
		}
		check(err)

		r.Write(decrypt(buff[:n], nonceSize, gcm))
	}
}

func NewStreamer(filepath string) *Streamer {
	s := &Streamer{
		Filepath: filepath,
	}
	if len(s.key) == 0 {
		check(s.init())
	}
	return s
}

func encrypt(data []byte, gcm cipher.AEAD) []byte {

	nonce := make([]byte, gcm.NonceSize())
	_, err := io.ReadFull(rand.Reader, nonce)
	check(err)
	return gcm.Seal(nonce, nonce, data, nil)
}

func decrypt(data []byte, nonceSize int, gcm cipher.AEAD) []byte {
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	out, err := gcm.Open(nil, nonce, ciphertext, nil)
	check(err)
	return out
}
