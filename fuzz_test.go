package wkwcrypt

import "testing"

func FuzzDecryptWithKey(f *testing.F) {
	key := []byte("0123456789abcdef0123456789abcdef")
	f.Add("wkw1:b64:")
	f.Add("wkw1:b64:AA")
	f.Add("not-an-envelope")

	f.Fuzz(func(t *testing.T, encoded string) {
		_, _ = DecryptWithKey(encoded, key)
	})
}
