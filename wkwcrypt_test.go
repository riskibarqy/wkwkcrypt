package wkwcrypt

import (
	"errors"
	"strings"
	"testing"
)

func TestKeyRoundTrip(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := []byte{0, 1, 2, 'h', 'i', 0xff}
	aad := []byte("tenant:one")

	encoded, err := EncryptWithKey(plaintext, key, WithAAD(aad))
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}
	if !strings.HasPrefix(encoded, "wkw1:b64:") {
		t.Fatalf("EncryptWithKey() = %q, want wkw1:b64 prefix", encoded)
	}
	decrypted, err := DecryptWithKey(encoded, key, WithAAD(aad))
	if err != nil {
		t.Fatalf("DecryptWithKey() error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("DecryptWithKey() = %x, want %x", decrypted, plaintext)
	}
}

func TestKeyEncryptionUsesFreshNonce(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	first, err := EncryptWithKey([]byte("same input"), key)
	if err != nil {
		t.Fatalf("first EncryptWithKey() error = %v", err)
	}
	second, err := EncryptWithKey([]byte("same input"), key)
	if err != nil {
		t.Fatalf("second EncryptWithKey() error = %v", err)
	}
	if first == second {
		t.Fatal("EncryptWithKey() returned identical ciphertexts")
	}
}

func TestKeyDecryptionRejectsWrongAADAndTampering(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	encoded, err := EncryptWithKey([]byte("secret"), key, WithAAD([]byte("tenant:a")))
	if err != nil {
		t.Fatalf("EncryptWithKey() error = %v", err)
	}

	if _, err := DecryptWithKey(encoded, key, WithAAD([]byte("tenant:b"))); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("DecryptWithKey() wrong AAD error = %v, want ErrAuthentication", err)
	}

	tampered := encoded[:len(encoded)-1] + "A"
	if encoded[len(encoded)-1] == 'A' {
		tampered = encoded[:len(encoded)-1] + "B"
	}
	if _, err := DecryptWithKey(tampered, key); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("DecryptWithKey() tampered error = %v, want ErrAuthentication", err)
	}
}

func TestKeyValidationAndEncoding(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	if _, err := EncryptWithKey([]byte("value"), key[:31]); !errors.Is(err, ErrInvalidKey) {
		t.Fatalf("EncryptWithKey() invalid key error = %v, want ErrInvalidKey", err)
	}
	words, err := EncryptWithKey([]byte("value"), key, WithEncoding(EncodingWords))
	if err != nil {
		t.Fatalf("EncryptWithKey() words error = %v", err)
	}
	if !strings.HasPrefix(words, "wkw1:words:") {
		t.Fatalf("EncryptWithKey() words = %q, want wkw1:words prefix", words)
	}
	if _, err := DecryptWithKey(words, key); err != nil {
		t.Fatalf("DecryptWithKey() words error = %v", err)
	}
	if _, err := DecryptWithKey("wkw1:b64:not+url-safe", key); !errors.Is(err, ErrInvalidEncoding) {
		t.Fatalf("DecryptWithKey() malformed Base64 error = %v, want ErrInvalidEncoding", err)
	}
}

func TestPasswordRoundTrip(t *testing.T) {
	password := []byte("correct horse battery staple")
	plaintext := []byte("password protected")
	encoded, err := EncryptWithPassword(plaintext, password, WithAAD([]byte("record:42")))
	if err != nil {
		t.Fatalf("EncryptWithPassword() error = %v", err)
	}
	decrypted, err := DecryptWithPassword(encoded, password, WithAAD([]byte("record:42")))
	if err != nil {
		t.Fatalf("DecryptWithPassword() error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("DecryptWithPassword() = %q, want %q", decrypted, plaintext)
	}
	if _, err := DecryptWithPassword(encoded, []byte("wrong password"), WithAAD([]byte("record:42"))); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("DecryptWithPassword() wrong password error = %v, want ErrAuthentication", err)
	}

	words, err := EncryptWithPassword(plaintext, password, WithAAD([]byte("record:42")), WithEncoding(EncodingWords))
	if err != nil {
		t.Fatalf("EncryptWithPassword() words error = %v", err)
	}
	decrypted, err = DecryptWithPassword(words, password, WithAAD([]byte("record:42")))
	if err != nil {
		t.Fatalf("DecryptWithPassword() words error = %v", err)
	}
	if string(decrypted) != string(plaintext) {
		t.Fatalf("DecryptWithPassword() words = %q, want %q", decrypted, plaintext)
	}
}

func TestPasswordValidation(t *testing.T) {
	if _, err := EncryptWithPassword([]byte("value"), nil); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("EncryptWithPassword() error = %v, want ErrInvalidPassword", err)
	}
}

func TestPlaintextLimit(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	plaintext := make([]byte, MaxPlaintextSize+1)
	if _, err := EncryptWithKey(plaintext, key); !errors.Is(err, ErrPlaintextTooLarge) {
		t.Fatalf("EncryptWithKey() error = %v, want ErrPlaintextTooLarge", err)
	}
}
