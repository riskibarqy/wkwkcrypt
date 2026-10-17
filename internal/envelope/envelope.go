package envelope

import (
	"encoding/binary"
	"errors"
)

const (
	MaxSize = 2 * 1024

	ModeKey      byte = 1
	ModePassword byte = 2

	Version1     byte = 1
	SuiteXChaCha byte = 1
	KDFNone      byte = 0
	KDFArgon2id  byte = 1
	nonceSize         = 24
	saltSize          = 16
	tagSize           = 16
)

var (
	ErrInvalid            = errors.New("invalid envelope")
	ErrUnsupported        = errors.New("unsupported envelope")
	ErrUnsupportedVersion = errors.New("unsupported envelope version")
)

// Header contains the public, authenticated envelope fields through the nonce.
type Header struct {
	Mode        byte
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
	Salt        [saltSize]byte
	Nonce       [nonceSize]byte
}

// MarshalHeader serializes exactly the bytes authenticated alongside ciphertext.
func MarshalHeader(header Header) ([]byte, error) {
	if header.Mode != ModeKey && header.Mode != ModePassword {
		return nil, ErrUnsupported
	}

	length := 3 + 1 + 1 + 1 + 1 + nonceSize
	if header.Mode == ModePassword {
		length += 4 + 4 + 1 + saltSize
	}
	encoded := make([]byte, length)
	copy(encoded, "WKW")
	encoded[3] = Version1
	encoded[4] = header.Mode
	encoded[5] = SuiteXChaCha
	position := 6
	if header.Mode == ModeKey {
		encoded[position] = KDFNone
		position++
	} else {
		encoded[position] = KDFArgon2id
		position++
		binary.BigEndian.PutUint32(encoded[position:], header.MemoryKiB)
		position += 4
		binary.BigEndian.PutUint32(encoded[position:], header.Iterations)
		position += 4
		encoded[position] = header.Parallelism
		position++
		copy(encoded[position:], header.Salt[:])
		position += saltSize
	}
	copy(encoded[position:], header.Nonce[:])
	return encoded, nil
}

// Parse validates a complete binary envelope before any key derivation or AEAD work.
func Parse(payload []byte) (Header, []byte, []byte, error) {
	var header Header
	if len(payload) > MaxSize || len(payload) < 7+nonceSize+tagSize {
		return header, nil, nil, ErrInvalid
	}
	if string(payload[:3]) != "WKW" {
		return header, nil, nil, ErrInvalid
	}
	if payload[3] != Version1 {
		return header, nil, nil, ErrUnsupportedVersion
	}
	if payload[5] != SuiteXChaCha {
		return header, nil, nil, ErrUnsupported
	}

	header.Mode = payload[4]
	position := 6
	switch header.Mode {
	case ModeKey:
		if payload[position] != KDFNone {
			return header, nil, nil, ErrUnsupported
		}
		position++
	case ModePassword:
		if len(payload) < position+1+4+4+1+saltSize+nonceSize+tagSize || payload[position] != KDFArgon2id {
			return header, nil, nil, ErrInvalid
		}
		position++
		header.MemoryKiB = binary.BigEndian.Uint32(payload[position:])
		position += 4
		header.Iterations = binary.BigEndian.Uint32(payload[position:])
		position += 4
		header.Parallelism = payload[position]
		position++
		copy(header.Salt[:], payload[position:position+saltSize])
		position += saltSize
	default:
		return header, nil, nil, ErrUnsupported
	}
	copy(header.Nonce[:], payload[position:position+nonceSize])
	position += nonceSize
	if len(payload)-position < tagSize {
		return header, nil, nil, ErrInvalid
	}
	serializedHeader := append([]byte(nil), payload[:position]...)
	ciphertext := append([]byte(nil), payload[position:]...)
	return header, serializedHeader, ciphertext, nil
}

// Join appends an authenticated ciphertext to its serialized header.
func Join(header, ciphertext []byte) ([]byte, error) {
	if len(header)+len(ciphertext) > MaxSize || len(ciphertext) < tagSize {
		return nil, ErrInvalid
	}
	payload := make([]byte, 0, len(header)+len(ciphertext))
	payload = append(payload, header...)
	payload = append(payload, ciphertext...)
	return payload, nil
}
