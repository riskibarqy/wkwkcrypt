package codec

import (
	"bytes"
	"strings"
	"testing"
)

func FuzzDecode(f *testing.F) {
	f.Add(Prefix)
	f.Add(Encode([]byte{0x00, 0xff}))
	f.Add(Prefix + "AA")
	f.Add(Prefix + "AA=")
	f.Add("wkw1:words:alpha-beta")
	f.Add(EncodeWords([]byte{0x00, 0xff}))

	f.Fuzz(func(t *testing.T, encoded string) {
		payload, err := Decode(encoded)
		if err != nil {
			return
		}
		canonical := Encode(payload)
		if strings.HasPrefix(encoded, WordsPrefix) {
			canonical = EncodeWords(payload)
		}
		if canonical != encoded {
			t.Fatalf("Decode(%q) accepted noncanonical value; canonical = %q", encoded, canonical)
		}
	})
}

func FuzzEncodeDecodeWords(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0xff})
	f.Add(bytes.Repeat([]byte{0x42}, 128))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) > 2*1024 {
			t.Skip()
		}
		decoded, err := DecodeWords(EncodeWords(payload))
		if err != nil {
			t.Fatalf("DecodeWords(EncodeWords()) error = %v", err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("DecodeWords(EncodeWords()) = %x, want %x", decoded, payload)
		}
	})
}

func FuzzEncodeDecode(f *testing.F) {
	f.Add([]byte{0x00})
	f.Add([]byte{0x00, 0xff})
	f.Add(bytes.Repeat([]byte{0x42}, 128))

	f.Fuzz(func(t *testing.T, payload []byte) {
		if len(payload) == 0 || len(payload) > 2*1024 {
			t.Skip()
		}
		decoded, err := Decode(Encode(payload))
		if err != nil {
			t.Fatalf("Decode(Encode()) error = %v", err)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatalf("Decode(Encode()) = %x, want %x", decoded, payload)
		}
	})
}
