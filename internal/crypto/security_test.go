package crypto

import (
	"bytes"
	"errors"
	"testing"
)

func TestVersionHeaderAndRandomness(t *testing.T) {
	first, err := Encrypt([]byte("secret"), "password")
	if err != nil {
		t.Fatal(err)
	}

	second, err := Encrypt([]byte("secret"), "password")
	if err != nil {
		t.Fatal(err)
	}

	if !IsCurrent(first) || bytes.Equal(first, second) || bytes.Equal(first[len(magic):headerSize], second[len(magic):headerSize]) || bytes.Equal(first[headerSize:headerSize+nonceSize], second[headerSize:headerSize+nonceSize]) {
		t.Fatal("version or fresh randomness missing")
	}

	for _, index := range []int{0, len(magic), headerSize, len(first) - 1} {
		bad := bytes.Clone(first)
		bad[index] ^= 1
		if _, err := Decrypt(bad, "password"); err == nil {
			t.Fatalf("tampering accepted at %d", index)
		}
	}

	for n := len(magic); n < headerSize+nonceSize+tagSize; n++ {
		if _, err := Decrypt(first[:n], "password"); err == nil {
			t.Fatal("truncated v2 accepted")
		}
	}

	if _, err := Encrypt(nil, ""); err == nil {
		t.Fatal("empty password accepted")
	}
}

func TestLegacyIsExplicitOnly(t *testing.T) {
	salt := bytes.Repeat([]byte{1}, saltSize)
	aead, err := newAEAD("password", salt, true)
	if err != nil {
		t.Fatal(err)
	}

	nonce := bytes.Repeat([]byte{2}, nonceSize)
	legacy := aead.Seal(append(salt, nonce...), nonce, []byte("legacy"), nil)
	if _, err := Decrypt(legacy, "password"); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("silently accepted old format: %v", err)
	}

	plain, err := DecryptForMigration(legacy, "password")
	if err != nil || string(plain) != "legacy" {
		t.Fatalf("legacy migration: %q %v", plain, err)
	}

	legacy[len(legacy)-1] ^= 1
	if _, err := DecryptForMigration(legacy, "password"); err == nil {
		t.Fatal("legacy tamper accepted")
	}
}
