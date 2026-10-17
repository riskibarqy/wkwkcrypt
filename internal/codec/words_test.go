package codec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestBIP39EnglishDictionary(t *testing.T) {
	digest := sha256.Sum256([]byte(bip39English))
	const expectedSHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
	if actual := hex.EncodeToString(digest[:]); actual != expectedSHA256 {
		t.Fatalf("dictionary SHA-256 = %s, want %s", actual, expectedSHA256)
	}
	if len(wordList) != 2048 || len(wordIndex) != 2048 {
		t.Fatalf("dictionary size = %d/%d, want 2048", len(wordList), len(wordIndex))
	}
}

func TestWordRoundTrip(t *testing.T) {
	payload := append([]byte{0x00, 0xff}, bytes.Repeat([]byte{0x42}, 127)...)
	encoded := EncodeWords(payload)
	if !strings.HasPrefix(encoded, WordsPrefix) {
		t.Fatalf("EncodeWords() = %q, want words prefix", encoded)
	}
	decoded, err := DecodeWords(encoded)
	if err != nil {
		t.Fatalf("DecodeWords() error = %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("DecodeWords() = %x, want %x", decoded, payload)
	}
}

func TestWordCompatibilityVector(t *testing.T) {
	const expected = "wkw1:words:abandon-abandon-absurd-abandon-awake-account"
	payload := []byte{0x00, 0x01, 0x02, 0x03}
	if actual := EncodeWords(payload); actual != expected {
		t.Fatalf("EncodeWords() = %q, want %q", actual, expected)
	}
	decoded, err := DecodeWords(expected)
	if err != nil {
		t.Fatalf("DecodeWords() error = %v", err)
	}
	if !bytes.Equal(decoded, payload) {
		t.Fatalf("DecodeWords() = %x, want %x", decoded, payload)
	}
}

func TestDecodeWordsRejectsNoncanonicalInput(t *testing.T) {
	encoded := EncodeWords([]byte{0x01})
	words := strings.Split(strings.TrimPrefix(encoded, WordsPrefix), "-")
	lastIndex := wordIndex[words[len(words)-1]]
	words[len(words)-1] = wordList[lastIndex|1]
	withPadding := WordsPrefix + strings.Join(words, "-")

	for name, value := range map[string]string{
		"unknown word":    WordsPrefix + "notaword",
		"extra word":      encoded + "-abandon",
		"missing word":    WordsPrefix + strings.Join(words[:len(words)-1], "-"),
		"nonzero padding": withPadding,
		"wrong separator": strings.Replace(encoded, "-", "--", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeWords(value); err == nil {
				t.Fatal("DecodeWords() error = nil, want invalid input")
			}
		})
	}
}
