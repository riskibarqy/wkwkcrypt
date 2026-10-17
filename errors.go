package wkwcrypt

import "errors"

var (
	ErrInvalidKey         = errors.New("wkwcrypt: invalid key")
	ErrInvalidPassword    = errors.New("wkwcrypt: invalid password")
	ErrInvalidPayload     = errors.New("wkwcrypt: invalid payload")
	ErrInvalidEncoding    = errors.New("wkwcrypt: invalid encoding")
	ErrUnsupported        = errors.New("wkwcrypt: unsupported format")
	ErrUnsupportedVersion = errors.New("wkwcrypt: unsupported envelope version")
	ErrUnsafeParameters   = errors.New("wkwcrypt: unsafe KDF parameters")
	ErrAuthentication     = errors.New("wkwcrypt: authentication failed")
	ErrBusy               = errors.New("wkwcrypt: password operations are busy")
	ErrPlaintextTooLarge  = errors.New("wkwcrypt: plaintext exceeds limit")
)
