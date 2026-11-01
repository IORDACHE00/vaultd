package crypto

import "testing"

func TestEncryption(t *testing.T) {
	ciphertext, err := Encrypt([]byte("secret"), "password")

	if err != nil {
		t.Fatal(err)
	}

	plain, err := Decrypt(ciphertext, "password")
	if err != nil || string(plain) != "secret" {
		t.Fatalf("roundtrip: %q %v", plain, err)
	}

	if _, err := Decrypt(ciphertext, "wrong"); err == nil {
		t.Fatal("wrong password accepted")
	}

	ciphertext[len(ciphertext)-1] ^= 1
	if _, err := Decrypt(ciphertext, "password"); err == nil {
		t.Fatal("tampering accepted")
	}

	for n := 0; n < headerSize+nonceSize+tagSize; n++ {
		if _, err := Decrypt(make([]byte, n), "password"); err == nil {
			t.Fatalf("accepted truncated ciphertext of size %d", n)
		}
	}
}
