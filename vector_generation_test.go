package wkwcrypt

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	internalcipher "wkwkcrypt/internal/cipher"
	"wkwkcrypt/internal/codec"
	"wkwkcrypt/internal/envelope"
	"wkwkcrypt/internal/kdf"
)

type vectorSet struct {
	Format  string          `json:"format"`
	Vectors []vectorFixture `json:"vectors"`
}

type vectorFixture struct {
	Name         string `json:"name"`
	Mode         string `json:"mode"`
	KeyHex       string `json:"key_hex"`
	Password     string `json:"password"`
	SaltHex      string `json:"salt_hex"`
	NonceHex     string `json:"nonce_hex"`
	PlaintextHex string `json:"plaintext_hex"`
	AADHex       string `json:"aad_hex"`
	Encoded      string `json:"encoded"`
}

func TestV1CompatibilityVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/v1_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors vectorSet
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Format != "wkw1" {
		t.Fatalf("vector format = %q, want wkw1", vectors.Format)
	}

	for _, vector := range vectors.Vectors {
		t.Run(vector.Name, func(t *testing.T) {
			plaintext := decodeVectorHex(t, vector.PlaintextHex)
			aad := decodeVectorHex(t, vector.AADHex)
			nonce := decodeVectorHex(t, vector.NonceHex)
			if len(nonce) != internalcipher.NonceSize {
				t.Fatalf("nonce length = %d, want %d", len(nonce), internalcipher.NonceSize)
			}

			header := envelope.Header{}
			var key []byte
			switch vector.Mode {
			case "key":
				header.Mode = envelope.ModeKey
				key = decodeVectorHex(t, vector.KeyHex)
				decrypted, err := DecryptWithKey(vector.Encoded, key, WithAAD(aad))
				if err != nil {
					t.Fatalf("DecryptWithKey() error = %v", err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("DecryptWithKey() = %x, want %x", decrypted, plaintext)
				}
			case "password":
				header.Mode = envelope.ModePassword
				header.MemoryKiB = kdf.DefaultMemoryKiB
				header.Iterations = kdf.DefaultIterations
				header.Parallelism = kdf.DefaultParallelism
				salt := decodeVectorHex(t, vector.SaltHex)
				if len(salt) != kdf.SaltSize {
					t.Fatalf("salt length = %d, want %d", len(salt), kdf.SaltSize)
				}
				copy(header.Salt[:], salt)
				var err error
				key, err = kdf.Derive([]byte(vector.Password), salt, kdf.DefaultParameters())
				if err != nil {
					t.Fatalf("Derive() error = %v", err)
				}
				decrypted, err := DecryptWithPassword(vector.Encoded, []byte(vector.Password), WithAAD(aad))
				if err != nil {
					t.Fatalf("DecryptWithPassword() error = %v", err)
				}
				if !bytes.Equal(decrypted, plaintext) {
					t.Fatalf("DecryptWithPassword() = %x, want %x", decrypted, plaintext)
				}
			default:
				t.Fatalf("unsupported vector mode %q", vector.Mode)
			}

			copy(header.Nonce[:], nonce)
			serializedHeader, err := envelope.MarshalHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			additionalData, err := frameAdditionalData(serializedHeader, aad)
			if err != nil {
				t.Fatal(err)
			}
			ciphertext, err := internalcipher.Seal(key, nonce, plaintext, additionalData)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := envelope.Join(serializedHeader, ciphertext)
			if err != nil {
				t.Fatal(err)
			}
			if encoded := codec.Encode(payload); encoded != vector.Encoded {
				t.Fatalf("encoded vector = %q, want %q", encoded, vector.Encoded)
			}
		})
	}
}

func TestUnsupportedVersion(t *testing.T) {
	key := []byte("0123456789abcdef0123456789abcdef")
	encoded, err := EncryptWithKey([]byte("value"), key)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := codec.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	payload[3] = 2
	if _, err := DecryptWithKey(codec.Encode(payload), key); err != ErrUnsupportedVersion {
		t.Fatalf("DecryptWithKey() error = %v, want ErrUnsupportedVersion", err)
	}
}

func decodeVectorHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q): %v", value, err)
	}
	return decoded
}
