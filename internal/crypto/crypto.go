package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	magic      = "vaultd\x00\x02"
	saltSize   = 16
	nonceSize  = 12
	tagSize    = 16
	headerSize = len(magic) + saltSize
)

var ErrLegacyFormat = errors.New("legacy vault format: stop the daemon and run 'vaultd migrate'")

func IsCurrent(data []byte) bool { return bytes.HasPrefix(data, []byte(magic)) }

// Fixed versioned costs cannot be inflated by an unauthenticated file header.
// These parameters should be benchmarked on the deployment hardware.
func newAEAD(password string, salt []byte, legacy bool) (cipher.AEAD, error) {
	pw := []byte(password)
	defer clear(pw)
	var key []byte

	if legacy {
		key = pbkdf2.Key(pw, salt, 100000, 32, sha256.New)
	} else {
		key = argon2.IDKey(pw, salt, 3, 64*1024, 1, 32)
	}

	defer clear(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return cipher.NewGCM(block)
}

// Encrypt writes v2 only: authenticated magic/version/salt, nonce, ciphertext.
func Encrypt(plaintext []byte, password string) ([]byte, error) {
	if password == "" {
		return nil, errors.New("password must not be empty")
	}

	header := make([]byte, headerSize)
	copy(header, magic)
	if _, err := io.ReadFull(rand.Reader, header[len(magic):]); err != nil {
		return nil, err
	}

	aead, err := newAEAD(password, header[len(magic):], false)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	out := append([]byte(nil), header...)
	out = append(out, nonce...)
	return aead.Seal(out, nonce, plaintext, header), nil
}

// Decrypt fails closed on the old weak format. Legacy decryption is available
// only to explicit migration/recovery, never as a fallback on auth failure.
func Decrypt(data []byte, password string) ([]byte, error) {
	if !IsCurrent(data) {
		return nil, ErrLegacyFormat
	}

	if len(data) < headerSize+nonceSize+tagSize {
		return nil, errors.New("truncated vault")
	}

	header := data[:headerSize]
	aead, err := newAEAD(password, header[len(magic):], false)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, data[headerSize:headerSize+nonceSize], data[headerSize+nonceSize:], header)
}

// DecryptForMigration accepts old snapshots during an explicit operation.
// Recognized v2 authentication failures are never retried as legacy.
func DecryptForMigration(data []byte, password string) ([]byte, error) {
	if IsCurrent(data) {
		return Decrypt(data, password)
	}

	if len(data) < saltSize+nonceSize+tagSize {
		return nil, errors.New("truncated legacy vault")
	}

	aead, err := newAEAD(password, data[:saltSize], true)
	if err != nil {
		return nil, err
	}

	return aead.Open(nil, data[saltSize:saltSize+nonceSize], data[saltSize+nonceSize:], nil)
}
