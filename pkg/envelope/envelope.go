package envelope

import (
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

	"github.com/google/tink/go/insecurecleartextkeyset"
	"github.com/google/tink/go/keyset"
	"github.com/google/tink/go/streamingaead"
)

const (
	signature string = "HRX2"
	version   int    = 2
)

type CipherStream interface {
	Encrypt() error
	Decrypt() error
}

type HorcruxStream struct {
	Filepath        string
	key             []byte
	encryptedKeyset []byte
	tinkHandle      *keyset.Handle
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
	s.tinkHandle = nil
}
func (s *HorcruxStream) SetKey(key []byte) {
	s.key = key
}
func (s *HorcruxStream) InitializeKey() error {
	dek, err := keyset.NewHandle(streamingaead.AES256GCMHKDF1MBKeyTemplate())
	if err != nil {
		return err
	}
	s.tinkHandle = dek

	buf := new(bytes.Buffer)
	writer := keyset.NewJSONWriter(buf)
	err = insecurecleartextkeyset.Write(dek, writer)
	if err != nil {
		return err
	}
	encryptedKey, err := s.encryptKey(buf)
	if err != nil {
		return err
	}
	s.encryptedKeyset = encryptedKey
	return nil

}

func (s *HorcruxStream) encryptKey(dek *bytes.Buffer) ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return nil, err
	}

	out := encrypt(dek.Bytes(), nonce, gcm)
	return out, nil
}

func (s *HorcruxStream) Encrypt() error {
	f, err := os.Open(s.Filepath)
	orgFname := filepath.Base(s.Filepath)
	if err != nil {
		return err
	}
	defer f.Close()

	outF, err := os.Create(s.Filepath + ".enc")
	if err != nil {
		return err
	}
	defer outF.Close()

	// Writing the metadata ----------------------------
	_, err = outF.Write([]byte(signature))
	if err != nil {
		return err
	}
	_, err = outF.Write([]byte{byte(version)})
	if err != nil {
		return err
	}

	originalFilenameLenSlice := binary.BigEndian.AppendUint16(nil, uint16(len(orgFname)))
	outF.Write(originalFilenameLenSlice)
	outF.Write([]byte(orgFname))

	encryptedKeysetLenSlice := binary.BigEndian.AppendUint16(nil, uint16(len(s.encryptedKeyset)))
	outF.Write(encryptedKeysetLenSlice)
	outF.Write(s.encryptedKeyset)

	// ----------------------------

	primitive, err := streamingaead.New(s.tinkHandle)
	if err != nil {
		return err
	}
	tinkWriter, err := primitive.NewEncryptingWriter(outF, nil)
	if err != nil {
		return err
	}

	_, err = io.Copy(tinkWriter, f)
	if err != nil {
		return err
	}

	if err = tinkWriter.Close(); err != nil {
		return err
	}

	return nil
}

func (s *HorcruxStream) Decrypt() error {
	f, err := os.Open(s.Filepath + ".enc")
	if err != nil {
		return err
	}
	defer f.Close()

	// Reading the metadata-------------------------------------------------
	signatureBuff := make([]byte, 4)
	n, err := io.ReadFull(f, signatureBuff)
	if err != nil {
		return err
	}
	if n < 4 || !bytes.Equal(signatureBuff, []byte(signature)) {
		return errors.New("Invalid signature!\n")
	}

	versionBuff := make([]byte, 1)
	n, err = io.ReadFull(f, versionBuff)
	if err != nil {
		return err
	}
	if n < 1 || !bytes.Equal(versionBuff, []byte{byte(version)}) {
		return errors.New("Invalid version!\n")
	}

	originalFilenameLen := make([]byte, 2)
	n, err = io.ReadFull(f, originalFilenameLen)
	if err != nil {
		return err
	}
	if n < 2 {
		return errors.New("Invalid original filename length!\n")
	}
	originalFilenameLenInt := int(binary.BigEndian.Uint16(originalFilenameLen))

	originalFilename := make([]byte, originalFilenameLenInt)
	n, err = io.ReadFull(f, originalFilename)
	if err != nil {
		return err
	}
	if n < originalFilenameLenInt {
		return errors.New("Invalid original filename!\n")
	}

	encryptedKeysetLen := make([]byte, 2)
	n, err = io.ReadFull(f, encryptedKeysetLen)
	if err != nil {
		return err
	}
	if n < 2 {
		return errors.New("Invalid encrypted keyset length!\n")
	}
	encryptedKeysetLenInt := int(binary.BigEndian.Uint16(encryptedKeysetLen))

	encryptedKeyset := make([]byte, encryptedKeysetLenInt)
	n, err = io.ReadFull(f, encryptedKeyset)
	if err != nil {
		return err
	}
	if n < encryptedKeysetLenInt {
		return errors.New("Invalid encrypted keyset!\n")
	}
	s.encryptedKeyset = encryptedKeyset
	//  ----------------------------------------------

	decryptedKeyset, err := s.decryptKeyset()
	if err != nil {
		return err
	}
	bytesReader := bytes.NewReader(decryptedKeyset)
	keysetReader := keyset.NewJSONReader(bytesReader)
	kh, err := insecurecleartextkeyset.Read(keysetReader)
	if err != nil {
		return err
	}
	decryptedKeyset = nil

	primitive, err := streamingaead.New(kh)
	if err != nil {
		return err
	}
	tinkReader, err := primitive.NewDecryptingReader(f, nil)
	if err != nil {
		return err
	}

	dir := filepath.Dir(s.Filepath)

	r, err := os.OpenFile(filepath.Join(dir, string(originalFilename)), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0666)
	if err != nil {
		return err
	}
	defer r.Close()

	_, err = io.Copy(r, tinkReader)
	if err != nil {
		return err
	}
	return nil
}

func NewHorcruxStream(filepath string) *HorcruxStream {
	s := &HorcruxStream{
		Filepath: filepath,
	}
	return s
}

func encrypt(data, nonce []byte, gcm cipher.AEAD) []byte {
	return gcm.Seal(nonce, nonce, data, nil)
}

func decrypt(data []byte, gcm cipher.AEAD) ([]byte, error) {
	nonceSize := gcm.NonceSize()
	nonce, cipherText := data[:nonceSize], data[nonceSize:]
	out, err := gcm.Open(nil, nonce, cipherText, nil)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *HorcruxStream) decryptKeyset() ([]byte, error) {
	block, err := aes.NewCipher(s.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	plainText, err := decrypt(s.encryptedKeyset, gcm)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}
