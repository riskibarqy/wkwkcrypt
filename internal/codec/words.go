package codec

import (
	_ "embed"
	"encoding/binary"
	"strings"

	"wkwkcrypt/internal/envelope"
)

const bitsPerWord = 11

//go:embed bip39_english.txt
var bip39English string

var (
	wordList  []string
	wordIndex map[string]uint16
)

func init() {
	words := strings.Fields(bip39English)
	if len(words) != 1<<bitsPerWord {
		panic("wkwcrypt: invalid embedded word list length")
	}

	indices := make(map[string]uint16, len(words))
	for index, word := range words {
		if !isLowerASCIIWord(word) {
			panic("wkwcrypt: invalid embedded word")
		}
		if _, exists := indices[word]; exists {
			panic("wkwcrypt: duplicate embedded word")
		}
		indices[word] = uint16(index)
	}
	wordList = words
	wordIndex = indices
}

// EncodeWords losslessly encodes envelope bytes using the frozen 2,048-word dictionary.
func EncodeWords(payload []byte) string {
	data := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(data, uint32(len(payload)))
	copy(data[4:], payload)

	totalBits := len(data) * 8
	wordCount := (totalBits + bitsPerWord - 1) / bitsPerWord
	words := make([]string, wordCount)
	for wordNumber := range words {
		var index uint16
		for bit := 0; bit < bitsPerWord; bit++ {
			index <<= 1
			bitPosition := wordNumber*bitsPerWord + bit
			if bitPosition < totalBits && bitAt(data, bitPosition) {
				index |= 1
			}
		}
		words[wordNumber] = wordList[index]
	}
	return WordsPrefix + strings.Join(words, "-")
}

// DecodeWords validates the canonical word grammar, payload length, and zero padding.
func DecodeWords(encoded string) ([]byte, error) {
	if len(encoded) > MaxEncodedSize || !strings.HasPrefix(encoded, WordsPrefix) {
		return nil, ErrInvalid
	}
	body := strings.TrimPrefix(encoded, WordsPrefix)
	if body == "" {
		return nil, ErrInvalid
	}
	words := strings.Split(body, "-")
	if len(words) < 3 {
		return nil, ErrInvalid
	}

	indices := make([]uint16, len(words))
	for position, word := range words {
		index, exists := wordIndex[word]
		if !exists {
			return nil, ErrInvalid
		}
		indices[position] = index
	}

	payloadLength := readBits(indices, 0, 32)
	if payloadLength > envelope.MaxSize {
		return nil, ErrInvalid
	}
	totalBits := 32 + int(payloadLength)*8
	expectedWords := (totalBits + bitsPerWord - 1) / bitsPerWord
	if len(indices) != expectedWords {
		return nil, ErrInvalid
	}
	for bit := totalBits; bit < len(indices)*bitsPerWord; bit++ {
		if wordBitAt(indices, bit) {
			return nil, ErrInvalid
		}
	}

	data := make([]byte, 4+int(payloadLength))
	for bit := 0; bit < totalBits; bit++ {
		if wordBitAt(indices, bit) {
			data[bit/8] |= 1 << (7 - bit%8)
		}
	}
	return data[4:], nil
}

func readBits(indices []uint16, start, count int) uint32 {
	var value uint32
	for bit := 0; bit < count; bit++ {
		value <<= 1
		if wordBitAt(indices, start+bit) {
			value |= 1
		}
	}
	return value
}

func bitAt(data []byte, bitPosition int) bool {
	return data[bitPosition/8]&(1<<(7-bitPosition%8)) != 0
}

func wordBitAt(indices []uint16, bitPosition int) bool {
	wordPosition := bitPosition / bitsPerWord
	bitInWord := bitPosition % bitsPerWord
	return indices[wordPosition]&(1<<(bitsPerWord-1-bitInWord)) != 0
}

func isLowerASCIIWord(word string) bool {
	if word == "" {
		return false
	}
	for _, character := range word {
		if character < 'a' || character > 'z' {
			return false
		}
	}
	return true
}
