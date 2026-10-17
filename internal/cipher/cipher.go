package cipher

import (
	"crypto/rand"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = chacha20poly1305.KeySize
	NonceSize = chacha20poly1305.NonceSizeX
)

var (
	ErrInvalidKey = errors.New("invalid key")
	ErrAuth       = errors.New("authentication failed")
)

// NewNonce returns a fresh XChaCha20-Poly1305 nonce from crypto/rand.
func NewNonce() ([NonceSize]byte, error) {
	var nonce [NonceSize]byte
	_, err := io.ReadFull(rand.Reader, nonce[:])
	return nonce, err
}

func Seal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize || len(nonce) != NonceSize {
		return nil, ErrInvalidKey
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

func Open(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(key) != KeySize || len(nonce) != NonceSize {
		return nil, ErrInvalidKey
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, ErrAuth
	}
	return plaintext, nil
}
