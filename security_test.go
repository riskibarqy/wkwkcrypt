package wkwcrypt

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/riskibarqy/wkwkcrypt/internal/codec"
	"github.com/riskibarqy/wkwkcrypt/internal/kdf"
)

func TestKeyEnvelopeRejectsWrongKeyAndHeaderTampering(t *testing.T) {
	key := make([]byte, 32)
	encoded, err := EncryptWithKey([]byte("security test"), key)
	if err != nil {
		t.Fatal(err)
	}
	wrongKey := make([]byte, 32)
	wrongKey[0] = 1
	if _, err := DecryptWithKey(encoded, wrongKey); !errors.Is(err, ErrAuthentication) {
		t.Fatalf("wrong key: got %v, want ErrAuthentication", err)
	}
	payload, err := codec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// The raw-key header is 7 fixed bytes followed by a 24-byte nonce.
	for i := 0; i < 31; i++ {
		modified := append([]byte(nil), payload...)
		modified[i] ^= 1
		_, err := DecryptWithKey(codec.Encode(modified), key)
		if err == nil {
			t.Fatalf("accepted modified header byte %d", i)
		}
		if i >= 7 && !errors.Is(err, ErrAuthentication) {
			t.Fatalf("modified nonce byte %d: got %v, want ErrAuthentication", i, err)
		}
	}
}

func TestTruncatedEnvelopesRejected(t *testing.T) {
	key := make([]byte, 32)
	password := []byte("password")
	keyEncoded, err := EncryptWithKey(nil, key)
	if err != nil {
		t.Fatal(err)
	}
	passwordEncoded, err := EncryptWithPassword(nil, password)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		encoded string
		decrypt func(string) error
	}{
		{"key", keyEncoded, func(s string) error { _, err := DecryptWithKey(s, key); return err }},
		{"password", passwordEncoded, func(s string) error { _, err := DecryptWithPassword(s, password); return err }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload, err := codec.Decode(tc.encoded)
			if err != nil {
				t.Fatal(err)
			}
			for length := 0; length < len(payload); length++ {
				if err := tc.decrypt(codec.Encode(payload[:length])); err == nil {
					t.Fatalf("accepted truncated payload of %d bytes", length)
				}
			}
		})
	}
}

func TestPasswordEnvelopeRejectsUnsafeParameters(t *testing.T) {
	password := []byte("password")
	encoded, err := EncryptWithPassword(nil, password)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		offset int
		value  uint32
		byte   bool
	}{
		{"zero memory", 7, 0, false},
		{"excess memory", 7, kdf.MaxMemoryKiB + 1, false},
		{"zero iterations", 11, 0, false},
		{"excess iterations", 11, kdf.MaxIterations + 1, false},
		{"zero parallelism", 15, 0, true},
		{"excess parallelism", 15, uint32(kdf.MaxParallelism) + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			modified := append([]byte(nil), payload...)
			if tc.byte {
				modified[tc.offset] = byte(tc.value)
			} else {
				binary.BigEndian.PutUint32(modified[tc.offset:], tc.value)
			}
			if _, err := DecryptWithPassword(codec.Encode(modified), password); !errors.Is(err, ErrUnsafeParameters) {
				t.Fatalf("got %v, want ErrUnsafeParameters", err)
			}
		})
	}
}
