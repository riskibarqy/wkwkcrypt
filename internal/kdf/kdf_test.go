package kdf

import (
	"errors"
	"testing"
)

func TestValidate(t *testing.T) {
	if err := Validate(DefaultParameters()); err != nil {
		t.Fatalf("Validate(DefaultParameters()) error = %v", err)
	}
	if err := Validate(Parameters{MemoryKiB: MaxMemoryKiB + 1, Iterations: 1, Parallelism: 1}); !errors.Is(err, ErrUnsafeParameters) {
		t.Fatalf("Validate() error = %v, want ErrUnsafeParameters", err)
	}
}

func TestDeriveRejectsWhenCapacityIsFull(t *testing.T) {
	slots <- struct{}{}
	slots <- struct{}{}
	defer func() {
		<-slots
		<-slots
	}()

	salt := make([]byte, SaltSize)
	_, err := Derive([]byte("password"), salt, DefaultParameters())
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("Derive() error = %v, want ErrBusy", err)
	}
}
