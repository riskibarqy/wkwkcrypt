// Package wkwcrypt provides authenticated encryption with URL-safe Base64 envelopes.
package wkwcrypt

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"math"

	internalcipher "wkwkcrypt/internal/cipher"
	"wkwkcrypt/internal/codec"
	"wkwkcrypt/internal/envelope"
	"wkwkcrypt/internal/kdf"
)

const (
	// MaxPlaintextSize bounds plaintext accepted by public encryption APIs.
	MaxPlaintextSize = 1024
)

// EncryptWithKey encrypts plaintext using an application-managed 32-byte key.
// It returns an unpadded URL-safe Base64 envelope unless another supported encoding is selected.
func EncryptWithKey(plaintext, key []byte, opts ...Option) (string, error) {
	if len(key) != internalcipher.KeySize {
		return "", ErrInvalidKey
	}
	if len(plaintext) > MaxPlaintextSize {
		return "", ErrPlaintextTooLarge
	}
	configured := applyOptions(opts)
	if err := validateEncryptionEncoding(configured.encoding); err != nil {
		return "", err
	}

	nonce, err := internalcipher.NewNonce()
	if err != nil {
		return "", err
	}
	header := envelope.Header{Mode: envelope.ModeKey, Nonce: nonce}
	return encrypt(plaintext, key, header, configured)
}

// DecryptWithKey decrypts an envelope created with EncryptWithKey.
func DecryptWithKey(ciphertext string, key []byte, opts ...Option) ([]byte, error) {
	if len(key) != internalcipher.KeySize {
		return nil, ErrInvalidKey
	}
	configured := applyOptions(opts)
	header, serializedHeader, encrypted, err := decodeEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}
	if header.Mode != envelope.ModeKey {
		return nil, ErrInvalidPayload
	}
	return decrypt(key, header, serializedHeader, encrypted, configured.aad)
}

// EncryptWithPassword encrypts plaintext using a non-empty password and Argon2id.
// Password mode is intentionally expensive and may return ErrBusy when its bounded capacity is full.
func EncryptWithPassword(plaintext, password []byte, opts ...Option) (string, error) {
	if len(password) == 0 {
		return "", ErrInvalidPassword
	}
	if len(plaintext) > MaxPlaintextSize {
		return "", ErrPlaintextTooLarge
	}
	configured := applyOptions(opts)
	if err := validateEncryptionEncoding(configured.encoding); err != nil {
		return "", err
	}

	var salt [kdf.SaltSize]byte
	if _, err := io.ReadFull(rand.Reader, salt[:]); err != nil {
		return "", err
	}
	params := kdf.DefaultParameters()
	key, err := derivePasswordKey(password, salt[:], params)
	if err != nil {
		return "", err
	}
	nonce, err := internalcipher.NewNonce()
	if err != nil {
		return "", err
	}
	header := envelope.Header{
		Mode:        envelope.ModePassword,
		MemoryKiB:   params.MemoryKiB,
		Iterations:  params.Iterations,
		Parallelism: params.Parallelism,
		Nonce:       nonce,
	}
	copy(header.Salt[:], salt[:])
	return encrypt(plaintext, key, header, configured)
}

// DecryptWithPassword decrypts an envelope created with EncryptWithPassword.
func DecryptWithPassword(ciphertext string, password []byte, opts ...Option) ([]byte, error) {
	configured := applyOptions(opts)
	header, serializedHeader, encrypted, err := decodeEnvelope(ciphertext)
	if err != nil {
		return nil, err
	}
	if header.Mode != envelope.ModePassword {
		return nil, ErrInvalidPayload
	}
	params := kdf.Parameters{
		MemoryKiB:   header.MemoryKiB,
		Iterations:  header.Iterations,
		Parallelism: header.Parallelism,
	}
	key, err := derivePasswordKey(password, header.Salt[:], params)
	if err != nil {
		return nil, err
	}
	return decrypt(key, header, serializedHeader, encrypted, configured.aad)
}

func encrypt(plaintext, key []byte, header envelope.Header, configured options) (string, error) {
	serializedHeader, err := envelope.MarshalHeader(header)
	if err != nil {
		return "", mapEnvelopeError(err)
	}
	additionalData, err := frameAdditionalData(serializedHeader, configured.aad)
	if err != nil {
		return "", err
	}
	ciphertext, err := internalcipher.Seal(key, header.Nonce[:], plaintext, additionalData)
	if err != nil {
		return "", mapCipherError(err)
	}
	payload, err := envelope.Join(serializedHeader, ciphertext)
	if err != nil {
		return "", mapEnvelopeError(err)
	}
	switch configured.encoding {
	case EncodingBase64:
		return codec.EncodeBase64(payload), nil
	case EncodingWords:
		return codec.EncodeWords(payload), nil
	default:
		return "", ErrInvalidEncoding
	}
}

func decrypt(key []byte, header envelope.Header, serializedHeader, ciphertext, aad []byte) ([]byte, error) {
	additionalData, err := frameAdditionalData(serializedHeader, aad)
	if err != nil {
		return nil, err
	}
	plaintext, err := internalcipher.Open(key, header.Nonce[:], ciphertext, additionalData)
	if err != nil {
		return nil, mapCipherError(err)
	}
	if len(plaintext) > MaxPlaintextSize {
		return nil, ErrInvalidPayload
	}
	return plaintext, nil
}

func decodeEnvelope(encoded string) (envelope.Header, []byte, []byte, error) {
	var zero envelope.Header
	payload, err := codec.Decode(encoded)
	if err != nil {
		return zero, nil, nil, ErrInvalidEncoding
	}
	header, serializedHeader, ciphertext, err := envelope.Parse(payload)
	if err != nil {
		return zero, nil, nil, mapEnvelopeError(err)
	}
	return header, serializedHeader, ciphertext, nil
}

func derivePasswordKey(password, salt []byte, params kdf.Parameters) ([]byte, error) {
	key, err := kdf.Derive(password, salt, params)
	if err == nil {
		return key, nil
	}
	switch {
	case errors.Is(err, kdf.ErrInvalidPassword):
		return nil, ErrInvalidPassword
	case errors.Is(err, kdf.ErrUnsafeParameters):
		return nil, ErrUnsafeParameters
	case errors.Is(err, kdf.ErrBusy):
		return nil, ErrBusy
	default:
		return nil, err
	}
}

func validateEncryptionEncoding(encoding Encoding) error {
	switch encoding {
	case EncodingBase64, EncodingWords:
		return nil
	default:
		return ErrInvalidEncoding
	}
}

func frameAdditionalData(header, aad []byte) ([]byte, error) {
	if uint64(len(header)) > math.MaxUint32 || uint64(len(aad)) > math.MaxUint32 {
		return nil, ErrInvalidPayload
	}
	framed := make([]byte, 8+len(header)+len(aad))
	binary.BigEndian.PutUint32(framed, uint32(len(header)))
	position := 4
	position += copy(framed[position:], header)
	binary.BigEndian.PutUint32(framed[position:], uint32(len(aad)))
	position += 4
	copy(framed[position:], aad)
	return framed, nil
}

func mapEnvelopeError(err error) error {
	if errors.Is(err, envelope.ErrUnsupportedVersion) {
		return ErrUnsupportedVersion
	}
	if errors.Is(err, envelope.ErrUnsupported) {
		return ErrUnsupported
	}
	return ErrInvalidPayload
}

func mapCipherError(err error) error {
	if errors.Is(err, internalcipher.ErrInvalidKey) {
		return ErrInvalidKey
	}
	if errors.Is(err, internalcipher.ErrAuth) {
		return ErrAuthentication
	}
	return err
}
