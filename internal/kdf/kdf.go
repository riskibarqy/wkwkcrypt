package kdf

import (
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultMemoryKiB   uint32 = 64 * 1024
	DefaultIterations  uint32 = 3
	DefaultParallelism uint8  = 4
	KeySize                   = 32
	SaltSize                  = 16

	MaxMemoryKiB   uint32 = 128 * 1024
	MaxIterations  uint32 = 5
	MaxParallelism uint8  = 4
)

var (
	ErrInvalidPassword  = errors.New("invalid password")
	ErrUnsafeParameters = errors.New("unsafe KDF parameters")
	ErrBusy             = errors.New("password operations are busy")
)

// Parameters are serialized in password-mode envelopes and are attacker-controlled on decrypt.
type Parameters struct {
	MemoryKiB   uint32
	Iterations  uint32
	Parallelism uint8
}

func DefaultParameters() Parameters {
	return Parameters{
		MemoryKiB:   DefaultMemoryKiB,
		Iterations:  DefaultIterations,
		Parallelism: DefaultParallelism,
	}
}

func Validate(params Parameters) error {
	if params.MemoryKiB == 0 || params.MemoryKiB > MaxMemoryKiB ||
		params.Iterations == 0 || params.Iterations > MaxIterations ||
		params.Parallelism == 0 || params.Parallelism > MaxParallelism {
		return ErrUnsafeParameters
	}
	return nil
}

var slots = make(chan struct{}, 2)

// Derive returns immediately when the fixed process-wide KDF capacity is exhausted.
func Derive(password, salt []byte, params Parameters) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrInvalidPassword
	}
	if len(salt) != SaltSize {
		return nil, ErrUnsafeParameters
	}
	if err := Validate(params); err != nil {
		return nil, err
	}

	select {
	case slots <- struct{}{}:
		defer func() { <-slots }()
	default:
		return nil, ErrBusy
	}

	return argon2.IDKey(password, salt, params.Iterations, params.MemoryKiB, params.Parallelism, KeySize), nil
}
