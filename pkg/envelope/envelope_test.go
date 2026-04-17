package envelope_test

import (
	"crypto/rand"
	"horcrux/pkg/envelope"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEncryptDecryptLifecycle(t *testing.T) {
	tempDir := t.TempDir()
	fileDir := filepath.Join(tempDir, "test.txt")

	if !assert.NoError(t, os.WriteFile(fileDir, []byte("This is some very secret data"), 0644)) {
		return
	}

	s := envelope.NewHorcruxStream(fileDir)
	kek, err := generateKEK()
	if err != nil {
		return
	}
	s.SetKey(kek)

	s.InitializeKey()

	var cipherStream envelope.CipherStream = s
	require.NoError(t, cipherStream.Encrypt())

	if !assert.NoError(t, os.Remove(fileDir)) {
		return
	}

	require.NoError(t, s.Decrypt())

	require.FileExists(t, fileDir)

	data, err := os.ReadFile(fileDir)
	require.NoError(t, err)

	require.Equal(t, []byte("This is some very secret data"), data)
}

func generateKEK() ([]byte, error) {
	kek := make([]byte, 32)
	_, err := rand.Read(kek)
	if err != nil {
		return nil, err
	}
	return kek, nil
}
