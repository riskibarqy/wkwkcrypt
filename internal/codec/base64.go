package codec

import (
	"encoding/base64"
	"errors"
	"strings"
)

const (
	Base64Prefix   = "wkw1:b64:"
	WordsPrefix    = "wkw1:words:"
	MaxEncodedSize = 32 * 1024

	// Prefix is retained for package callers that use the Base64 default.
	Prefix = Base64Prefix
)

var ErrInvalid = errors.New("invalid encoded envelope")

// Encode returns the canonical unpadded URL-safe Base64 representation.
func Encode(payload []byte) string {
	return EncodeBase64(payload)
}

func EncodeBase64(payload []byte) string {
	return Base64Prefix + base64.RawURLEncoding.EncodeToString(payload)
}

// Decode recognizes only canonical Base64 or word representations of a v1 envelope.
func Decode(encoded string) ([]byte, error) {
	switch {
	case strings.HasPrefix(encoded, Base64Prefix):
		return decodeBase64(encoded)
	case strings.HasPrefix(encoded, WordsPrefix):
		return DecodeWords(encoded)
	default:
		return nil, ErrInvalid
	}
}

func decodeBase64(encoded string) ([]byte, error) {
	if len(encoded) > MaxEncodedSize {
		return nil, ErrInvalid
	}
	value := strings.TrimPrefix(encoded, Base64Prefix)
	if value == "" {
		return nil, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || base64.RawURLEncoding.EncodeToString(payload) != value {
		return nil, ErrInvalid
	}
	return payload, nil
}
