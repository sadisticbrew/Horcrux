package envelope

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"os"
)

type CipherStream interface {
	Encrypt() error
	Decrypt()
}

type HorcruxStream struct {
	Filepath string
	key      []byte
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func (s *HorcruxStream) init() error {
	s.key = make([]byte, 32)
	_, err := rand.Read(s.key)
	if err != nil {
		return fmt.Errorf("Error generating the key: %w", err)
	}
	return nil
}

func (s *HorcruxStream) GetKey() *big.Int {
	return new(big.Int).SetBytes(s.key)
}
func (s *HorcruxStream) ClearKey() {
	s.key = nil
}
func (s *HorcruxStream) SetKey(key []byte) {
	s.key = key
}
func (s *HorcruxStream) InitializeKey() {
	s.key = make([]byte, 32)
	_, err := rand.Read(s.key)
	check(err)
}

func (s *HorcruxStream) Encrypt() error {

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

	baseNonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, baseNonce)
	check(err)
	r.Write(baseNonce)

	count := 0

	for {
		n, err := io.ReadFull(reader, buff)
		if n < len(buff) {
			fmt.Println("read bytes less than the buff", n)
		}
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			nonce := makeCombinedNonce(count, baseNonce, gcm)
			count++
			r.Write(encrypt(buff[:n], nonce, gcm))
			break
		}
		check(err)

		nonce := makeCombinedNonce(count, baseNonce, gcm)
		count++

		r.Write(encrypt(buff[:n], nonce, gcm))
	}

	return nil
}
func (s *HorcruxStream) Decrypt() {
	f, err := os.Open(s.Filepath + ".enc")
	check(err)
	defer f.Close()
	r, err := os.Create(s.Filepath + ".dec")
	check(err)
	defer r.Close()

	block, err := aes.NewCipher(s.key)
	check(err)
	gcm, err := cipher.NewGCM(block)
	check(err)

	nonceSize := gcm.NonceSize()
	targetReadSize := 4096 + gcm.Overhead()
	reader := bufio.NewReaderSize(f, targetReadSize)

	buff := make([]byte, targetReadSize)

	baseNonce := make([]byte, nonceSize)
	_, err = io.ReadFull(reader, baseNonce)
	check(err)

	count := 0

	for {
		n, err := io.ReadFull(reader, buff)

		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			nonce := makeCombinedNonce(count, baseNonce, gcm)
			count++
			r.Write(decrypt(buff[:n], nonce, gcm))
			break
		}
		check(err)

		nonce := makeCombinedNonce(count, baseNonce, gcm)
		count++

		r.Write(decrypt(buff[:n], nonce, gcm))
	}
}

func NewHorcruxStream(filepath string) *HorcruxStream {
	s := &HorcruxStream{
		Filepath: filepath,
	}
	return s
}

func makeCombinedNonce(count int, baseNonce []byte, gcm cipher.AEAD) []byte {
	countArray := make([]byte, 8)
	nonce := make([]byte, gcm.NonceSize())
	copy(nonce, baseNonce)
	binary.BigEndian.PutUint64(countArray, uint64(count))
	last8 := nonce[len(nonce)-8:]
	for i := range 8 {
		last8[i] ^= countArray[i]
	}
	return nonce
}

func encrypt(data, nonce []byte, gcm cipher.AEAD) []byte {
	return gcm.Seal(nil, nonce, data, nil)
}

func decrypt(data, nonce []byte, gcm cipher.AEAD) []byte {
	// nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	out, err := gcm.Open(nil, nonce, data, nil)
	check(err)
	return out
}

func main() {
	s := NewHorcruxStream("/home/caffeine/Documents/projects_backup.zip")
	s.Encrypt()
	s.Decrypt()
}
