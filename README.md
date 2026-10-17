# WKWCrypt

WKWCrypt is an experimental Go library for authenticated encryption of small byte values.

The current implementation supports:

- 32-byte application-managed keys with XChaCha20-Poly1305;
- password-derived keys using Argon2id with a fresh salt and bounded concurrent work;
- authenticated additional data (AAD);
- canonical unpadded URL-safe Base64 envelopes in the `wkw1:b64:<payload>` form; and
- a 2,048-word BIP-0039 English representation in the `wkw1:words:<word>-...` form.

The word representation is an encoding only, not a BIP-0039 mnemonic or wallet backup. The exact experimental `wkw1` envelope contract, word-list pin, and compatibility vectors are documented in `FORMAT.md`.

## Usage

The package encrypts small byte payloads. Keep raw keys in a proper key-management system and supply exactly the same AAD when decrypting.

```go
package main

import (
	"crypto/rand"
	"log"

	"wkwkcrypt" // Replace with the published module path before release.
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatal(err)
	}

	ciphertext, err := wkwkcrypt.EncryptWithKey(
		[]byte("launch code"),
		key,
		wkwkcrypt.WithAAD([]byte("account:42")),
		wkwkcrypt.WithEncoding(wkwkcrypt.EncodingWords), // Optional; Base64 is the default.
	)
	if err != nil {
		log.Fatal(err)
	}

	plaintext, err := wkwkcrypt.DecryptWithKey(
		ciphertext,
		key,
		wkwkcrypt.WithAAD([]byte("account:42")),
	)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("%s", plaintext)
}
```

For passwords, use `EncryptWithPassword` and `DecryptWithPassword` with the same AAD options. The library derives an encryption key with Argon2id; callers must still protect the password and handle decryption failures as authentication failures.

## Development

GitHub Actions runs the full verification suite on pushes and pull requests. Run it locally with:

```sh
go test ./...
go test -race ./...
go vet ./...
```

It also runs short fuzzing sessions for the public decrypt path, envelope parser, and both codecs. Run the same commands locally before changing the experimental `wkw1` format.

## Benchmarks

`benchmark_test.go` measures raw-key encryption/decryption for 16 B, 128 B, and 1 KiB payloads, plus password encryption for a 128-byte payload. Benchmark locally; results depend on the CPU and are intentionally not used as a CI pass/fail gate.

```sh
go test -bench=. -benchmem ./...
```

Latest baseline, captured on an Apple M4 (`darwin/arm64`):

```text
BenchmarkKeyEncryption/16B       614.3 ns/op   26.05 MB/s   632 B/op   11 allocs/op
BenchmarkKeyEncryption/128B      767.3 ns/op  166.82 MB/s  1304 B/op   11 allocs/op
BenchmarkKeyEncryption/1024B      2.199 us/op 465.64 MB/s  7160 B/op   11 allocs/op

BenchmarkKeyDecryption/16B       444.4 ns/op   36.00 MB/s   528 B/op   10 allocs/op
BenchmarkKeyDecryption/128B      625.5 ns/op  204.62 MB/s  1152 B/op   10 allocs/op
BenchmarkKeyDecryption/1024B      2.267 us/op 451.78 MB/s  6624 B/op   10 allocs/op

BenchmarkPasswordEncryption     30.55 ms/op      0 MB/s  67,120,730 B/op  102 allocs/op
```
