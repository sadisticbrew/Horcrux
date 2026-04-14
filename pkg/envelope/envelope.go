package envelope

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
)

const (
	signature string = "HRX1"
	version   int    = 1
)

type CipherStream interface {
	Encrypt(int) error
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

func (s *HorcruxStream) Encrypt(chunkSize int) error {

	if chunkSize < 128 {
		return fmt.Errorf("chunk size must be at least 128 bytes")
	}

	f, err := os.Open(s.Filepath)
	if err != nil {
		return err
	}
	baseFilename := filepath.Base(s.Filepath)
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

	baseNonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, baseNonce)
	if err != nil {
		return err
	}

	// Metadata section:
	// Fixed 21 byte metadata written to start of every encrypted file:
	// bytes 0-3: Unique signature `HRX1`
	// byte 4: the version
	// byte 5-8: Chunksize converted to uint32
	// 9-20 : The baseNonce
	//
	// The variable part:
	// byte 21-22: the original file name length (N)
	// byte 23-N: original file name converted to raw bytes
	r.Write([]byte(signature))
	r.Write([]byte{byte(1)})

	chunkSizeSlice := binary.BigEndian.AppendUint32(nil, uint32(chunkSize))
	r.Write(chunkSizeSlice)

	fmt.Println("Writing chunksize: ", chunkSize, chunkSizeSlice)
	r.Write(baseNonce)

	originalFilenameLenSlice := binary.BigEndian.AppendUint16(nil, uint16(len(baseFilename)))
	r.Write(originalFilenameLenSlice)
	fmt.Println("Writing org filename len: ", len(baseFilename), originalFilenameLenSlice)
	r.Write([]byte(baseFilename))

	buff := make([]byte, chunkSize)

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

	block, err := aes.NewCipher(s.key)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Reading the metadata
	signatureBuff := make([]byte, 4)
	n, err := io.ReadFull(f, signatureBuff)
	if err != nil {
		return err
	}
	if n < 4 || !bytes.Equal(signatureBuff, []byte(signature)) {
		return errors.New("Invalid signature!\n")
	}
	fmt.Println("Read signature", string(signatureBuff))

	versionBuff := make([]byte, 1)
	n, err = io.ReadFull(f, versionBuff)
	if err != nil {
		return err
	}
	if n < 1 || !bytes.Equal(versionBuff, []byte{byte(version)}) {
		return errors.New("Invalid version!\n")
	}
	fmt.Println("Read version", versionBuff)

	chunkSize := make([]byte, 4)
	n, err = io.ReadFull(f, chunkSize)
	if err != nil {
		return err
	}
	if n < 4 {
		return errors.New("Invalid chunk size!\n")
	}
	chunkSizeInt := int(binary.BigEndian.Uint32(chunkSize))
	fmt.Println("Read chunksize: ", chunkSizeInt, chunkSize)

	nonceSize := gcm.NonceSize()
	targetReadSize := chunkSizeInt + gcm.Overhead()
	reader := bufio.NewReaderSize(f, targetReadSize)

	buff := make([]byte, targetReadSize)

	baseNonce := make([]byte, nonceSize)
	_, err = io.ReadFull(reader, baseNonce)
	if err != nil {
		return err
	}
	fmt.Println("Read baseNonce ")

	originalFilenameLen := make([]byte, 2)
	n, err = io.ReadFull(reader, originalFilenameLen)
	if err != nil {
		return err
	}
	if n < 2 {
		return errors.New("Invalid original filename length!\n")
	}

	originalFilenameLenInt := int(binary.BigEndian.Uint16(originalFilenameLen))
	fmt.Println("Read org filename length", originalFilenameLenInt)
	originalFilename := make([]byte, originalFilenameLenInt)
	n, err = io.ReadFull(reader, originalFilename)
	if err != nil {
		return err
	}
	if n < originalFilenameLenInt {
		return errors.New("Invalid original filename!\n")
	}
	fmt.Println(string(originalFilename))

	dir := filepath.Dir(s.Filepath)
	fmt.Println("Writing to: ", filepath.Join(dir, string(originalFilename)))
	r, err := os.Create(filepath.Join(dir, string(originalFilename)))
	if err != nil {
		return err
	}
	defer r.Close()

	count := 0

	for {
		// fmt.Println("I reached the for loop")
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
