package wkwcrypt

import (
	"bytes"
	"strconv"
	"testing"
)

func BenchmarkKeyEncryption(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, size := range []int{16, 128, 1024} {
		plaintext := bytes.Repeat([]byte{0x42}, size)
		b.Run(benchmarkName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if _, err := EncryptWithKey(plaintext, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkKeyDecryption(b *testing.B) {
	key := []byte("0123456789abcdef0123456789abcdef")
	for _, size := range []int{16, 128, 1024} {
		plaintext := bytes.Repeat([]byte{0x42}, size)
		encoded, err := EncryptWithKey(plaintext, key)
		if err != nil {
			b.Fatal(err)
		}
		b.Run(benchmarkName(size), func(b *testing.B) {
			b.ReportAllocs()
			b.SetBytes(int64(size))
			for i := 0; i < b.N; i++ {
				if _, err := DecryptWithKey(encoded, key); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkPasswordEncryption(b *testing.B) {
	plaintext := bytes.Repeat([]byte{0x42}, 128)
	password := []byte("benchmark-password")
	b.ReportAllocs()
	b.SetBytes(int64(len(plaintext)))
	for i := 0; i < b.N; i++ {
		if _, err := EncryptWithPassword(plaintext, password); err != nil {
			b.Fatal(err)
		}
	}
}

func benchmarkName(size int) string {
	return strconv.Itoa(size) + "B"
}
