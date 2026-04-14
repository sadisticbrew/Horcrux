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
	Decrypt() error
}

type HorcruxStream struct {
	Filepath string
	key      []byte
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
func (s *HorcruxStream) InitializeKey() error {
	s.key = make([]byte, 32)
	_, err := rand.Read(s.key)
	if err != nil {
		return err
	}
	return nil
}

func (s *HorcruxStream) Encrypt() error {

	f, err := os.Open(s.Filepath)
	if err != nil {
		return err
	}
	defer f.Close()
	r, err := os.Create(s.Filepath + ".enc")
	if err != nil {
		return err
	}
	defer r.Close()

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	reader := bufio.NewReader(f)
	buff := make([]byte, 4096)

	baseNonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, baseNonce)
	if err != nil {
		return err
	}
	r.Write(baseNonce)

	count := 0

	for {
		n, err := io.ReadFull(reader, buff)
		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			nonce := makeCombinedNonce(count, baseNonce, gcm)
			count++
			r.Write(encrypt(buff[:n], nonce, gcm))
			break
		}
		if err != nil {
			return err
		}

		nonce := makeCombinedNonce(count, baseNonce, gcm)
		count++

		_, err = r.Write(encrypt(buff[:n], nonce, gcm))
		if err != nil {
			return err
		}
	}

	return nil
}
func (s *HorcruxStream) Decrypt() error {
	f, err := os.Open(s.Filepath + ".enc")
	if err != nil {
		return err
	}
	defer f.Close()

	r, err := os.Create(s.Filepath + ".dec")
	if err != nil {
		return err
	}
	defer r.Close()

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	nonceSize := gcm.NonceSize()
	targetReadSize := 4096 + gcm.Overhead()
	reader := bufio.NewReaderSize(f, targetReadSize)

	buff := make([]byte, targetReadSize)

	baseNonce := make([]byte, nonceSize)
	_, err = io.ReadFull(reader, baseNonce)
	if err != nil {
		return err
	}

	count := 0

	for {
		n, err := io.ReadFull(reader, buff)

		if err == io.EOF {
			break
		}
		if err == io.ErrUnexpectedEOF {
			nonce := makeCombinedNonce(count, baseNonce, gcm)
			count++
			data, err := decrypt(buff[:n], nonce, gcm)
			if err != nil {
				return err
			}
			r.Write(data)
			break
		}
		if err != nil {
			return err
		}

		nonce := makeCombinedNonce(count, baseNonce, gcm)
		count++

		data, err := decrypt(buff[:n], nonce, gcm)
		if err != nil {
			return err
		}

		_, err = r.Write(data)
		if err != nil {
			return err
		}
	}
	return nil
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

func decrypt(data, nonce []byte, gcm cipher.AEAD) ([]byte, error) {
	out, err := gcm.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}
