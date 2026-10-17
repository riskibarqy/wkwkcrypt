# WKWCrypt — Technical Design (Proposed)

**Status:** Design proposal for v0.1.0. This document specifies a consistent implementation direction; wire-format details must be frozen and verified with test vectors before release.

## 1. Separation of concerns

```text
plaintext + application key/password
                 |
       [optional Argon2id]
                 |
         XChaCha20-Poly1305
                 |
    versioned authenticated envelope
                 |
       +---------+---------+
       |                   |
   word codec          base64url codec
       |                   |
       +---------+---------+
                 |
          transport string
```

Encryption must never depend on the funny-word dictionary. The dictionary is a reversible encoding table, not a secret.

## 2. Packages

```text
wkwcrypt/
├── go.mod
├── README.md
├── PRD.md
├── TECHNICAL_DESIGN.md
├── SECURITY.md
├── TEST_PLAN.md
├── wkwcrypt.go
├── options.go
├── errors.go
├── internal/
│   ├── cipher/       # XChaCha20-Poly1305 wrapper
│   ├── kdf/          # Argon2id derivation and bounds
│   ├── envelope/     # binary serialization, parsing, authenticated framing
│   └── codec/        # base64url and funny-word codecs
├── testdata/         # frozen format compatibility vectors
└── examples/
    ├── rawkey/
    └── password/
```

Favor a few small packages over abstract factories. Public entry points should depend on internal components; internal cryptographic packages should not depend on codecs.

## 3. Cryptographic primitives

- **AEAD:** `golang.org/x/crypto/chacha20poly1305.NewX(key)`.
- **Key:** 32 bytes.
- **Nonce:** 24 random bytes per encryption from `crypto/rand`.
- **Tag:** 16 bytes appended by AEAD.
- **KDF (password mode):** `golang.org/x/crypto/argon2.IDKey`.
- **Initial Argon2id params:** memory 64 MiB (`64*1024` KiB), iterations 3, threads 4, 32-byte output.
- **Salt:** random 16 bytes per password encryption.
- **Encoding:** 2,048-word dictionary (11 bits per word) or unpadded Base64 URL-safe.

For raw-key mode, **do not** add Argon2id or salt: the caller is responsible for secure key generation and storage.

## 4. Textual formats

```text
wkw1:words:<word>-<word>-...   # humorous, long
wkw1:b64:<unpadded-base64url>  # compact
```

The parser must require an exact prefix and reject unknown codecs or versions. The chosen codec has no impact on the binary envelope or cryptographic guarantees.

## 5. Proposed v1 binary envelope

All integers use big-endian encoding. All variant fields are explicitly bounded. Illustrative field order:

| Field | Raw-key mode | Password mode |
|---|---|---|
| Magic | 3 bytes: `WKW` | same |
| Format version | 1 byte: `1` | same |
| Mode | 1 byte: `1` | 1 byte: `2` |
| Cipher suite | 1 byte: `1` (XChaCha20-Poly1305) | same |
| KDF identifier | 1 byte: `0` | 1 byte: `1` (Argon2id) |
| Argon2id memory KiB | absent | uint32 |
| Argon2id iterations | absent | uint32 |
| Argon2id parallelism | absent | uint8 |
| Salt | absent | 16 bytes |
| Nonce | 24 bytes | 24 bytes |
| Ciphertext + tag | variable, ≥16 bytes | variable, ≥16 bytes |

**Authentication boundary:** Serialize the complete header through nonce. Call AEAD with an unambiguous framing of `(header, external AAD)` as associated data. For example, `uint32(len(header)) || header || uint32(len(aad)) || aad`. This binds the version, mode, KDF parameters, salt, nonce, and supplied AAD to the ciphertext. Since the header is public, do not place secrets in it.

**Parsing before authentication:** Treat all envelope fields as attacker-controlled until AEAD verification. Validate lengths and KDF limits before computing the key; never trust a ciphertext-provided memory setting without enforcing caps.

## 6. Exact reversible word encoding

The v1 word encoder should operate on arbitrary binary envelope bytes, not raw plaintext.

1. Check binary input length against `MaxEnvelopeSize`.
2. Build a byte sequence: `uint32_be(payload_length) || payload`.
3. Read the byte sequence as a big-endian bitstream.
4. Split into 11-bit indices; pad the **last group with zero bits** if required.
5. Map each index to one of exactly 2,048 immutable dictionary words.
6. Join words with ASCII hyphen `-`.

Decode reverses this:

1. Validate characters, separators, word count, and known dictionary values.
2. Turn word indices into a bitstream and decode its initial 32-bit payload length.
3. Reject lengths greater than `MaxEnvelopeSize` before allocating the payload.
4. Require **exactly** `ceil((32 + payload_length*8)/11)` words.
5. Ensure all padding bits after the declared data are zero.
6. Recover exactly `payload_length` bytes; reject noncanonical representation.

The leading 32-bit length is **word-codec framing**; it is not part of the encrypted envelope and is not a secret. It prevents ambiguity from the padding required by 11-bit groups.

The dictionary must contain simple, unique, lowercase ASCII tokens without hyphens, with index ordering fixed permanently for v1. Do not generate a dictionary by hashing, reshuffling, or locale-dependent sorting at runtime.

### Why word output is long

A raw-key encryption of 11 bytes has roughly 11 bytes of plaintext + 24-byte nonce + 16-byte tag + a small header. A password envelope also adds a 16-byte salt and Argon2id parameters. At 11 bits/word, these commonly require **roughly 45–70 words** for an 11-byte message. This is expected, not a defect.

## 7. API sketch

```go
type Encoding string
const (
    EncodingWords  Encoding = "words"
    EncodingBase64 Encoding = "b64"
)

type Option func(*options)

func EncryptWithKey(plaintext, key []byte, opts ...Option) (string, error)
func DecryptWithKey(encoded string, key []byte, opts ...Option) ([]byte, error)
func EncryptWithPassword(plaintext, password []byte, opts ...Option) (string, error)
func DecryptWithPassword(encoded string, password []byte, opts ...Option) ([]byte, error)

func WithEncoding(enc Encoding) Option // encryption only
func WithAAD(aad []byte) Option
```

Use `[]byte` rather than requiring UTF-8 strings for plaintext. `Decrypt*` auto-detects the codec, but never silently changes cryptographic mode. Avoid exposing an option that can reduce key size or disable authentication.

## 8. Concurrency and performance

- Raw-key entry points must be safe to call concurrently and must not mutate caller-provided input.
- Avoid retaining caller secrets in shared mutable objects.
- A password-mode semaphore should limit concurrent Argon2id operations (provisional maximum two per process). Do not enqueue unlimited requests; return a resource/busy error or support context-aware cancellation if capacity is exhausted.
- Prefer configuring limits via a constructor or options, rather than mutable globals. If API changes are needed, settle them before v1.0.0.
- Limit encoded text to 32 KiB and decoded binary envelope to 2 KiB by default, checking limits early.
- Benchmark the cipher, KDF, and codecs independently to isolate bottlenecks.

## 9. Compatibility policy

- `wkw1` denotes a stable envelope/codec contract, not just a marketing version.
- Store deterministic test vectors for both codecs and both key modes.
- Any change to dictionary index ordering requires a new codec identifier/version.
- Any breaking envelope change requires a new format version. Unsupported versions return a clear error.
- Key rotation or key IDs belong to future versions; callers must maintain key provenance in MVP.

## 10. Implementation sequence

1. Define and test envelope serialization and authentication framing.
2. Implement raw-key authenticated encryption and error handling.
3. Implement Argon2id with early limit validation and bounded concurrency.
4. Implement v1 frozen word dictionary and canonical codec.
5. Implement Base64 URL-safe codec and public API.
6. Add AAD tests, fuzz tests, vectors, CI, and benchmarks.

## References

- XChaCha20-Poly1305 Go package: https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
- Argon2 Go package: https://pkg.go.dev/golang.org/x/crypto/argon2
- RFC 9106 (Argon2): https://www.rfc-editor.org/rfc/rfc9106
