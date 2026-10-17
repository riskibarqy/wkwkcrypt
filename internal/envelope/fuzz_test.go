package envelope

import (
	"bytes"
	"testing"
)

func FuzzParse(f *testing.F) {
	valid := append([]byte("WKW\x01\x01\x01\x00"), make([]byte, nonceSize+tagSize)...)
	f.Add(valid)
	f.Add(bytes.Repeat([]byte{0xff}, MaxSize+1))

	f.Fuzz(func(t *testing.T, payload []byte) {
		header, serializedHeader, ciphertext, err := Parse(payload)
		if err != nil {
			return
		}
		if len(payload) > MaxSize || len(serializedHeader)+len(ciphertext) != len(payload) {
			t.Fatalf("Parse() accepted invalid envelope shape")
		}
		reencodedHeader, err := MarshalHeader(header)
		if err != nil {
			t.Fatalf("MarshalHeader(Parse()) error = %v", err)
		}
		if !bytes.Equal(reencodedHeader, serializedHeader) {
			t.Fatalf("MarshalHeader(Parse()) changed header")
		}
		joined, err := Join(serializedHeader, ciphertext)
		if err != nil {
			t.Fatalf("Join(Parse()) error = %v", err)
		}
		if !bytes.Equal(joined, payload) {
			t.Fatalf("Join(Parse()) changed envelope")
		}
	})
}
