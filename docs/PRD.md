# WKWCrypt — Product Requirements Document

**Status:** Draft  
**Target release:** v0.1.0 (MVP)  
**Product:** Open-source Go library  
**Proposed license:** MIT  
**Last updated:** 2026-10-16

## 1. Overview

WKWCrypt encrypts small values with established authenticated encryption and represents the resulting ciphertext as reversible sequences of humorous words. It also offers a compact, URL-safe Base64 representation.

**Example (illustrative only):**

```go
key := make([]byte, 32)
if _, err := rand.Read(key); err != nil {
    return err
}

ciphertext, err := wkwcrypt.EncryptWithKey(
    []byte("hello world"), key,
    wkwcrypt.WithEncoding(wkwcrypt.EncodingWords),
)
if err != nil {
    return err
}
// ciphertext: "wkw1:words:sleepy-potato-angry-duck-..."

plaintext, err := wkwcrypt.DecryptWithKey(ciphertext, key)
// plaintext: []byte("hello world")
```

> **No security from word choice.** The words are an encoding of a standard encrypted payload, not a custom cipher. A short 2–4-word nickname cannot represent arbitrary authenticated ciphertext losslessly. Expect dozens of words even for short plaintexts.

### 1.1 Problem

Encrypted blobs are opaque and unpleasant to read aloud or identify visually. Random funny-name generators yield memorable outputs but cannot, by themselves, securely and reversibly encode arbitrary data.

### 1.2 Product vision

Provide secure, interoperable encryption with an optional amusing representation, without compromising confidentiality, integrity, correctness, or operational performance.

### 1.3 Target users

- Go developers encrypting short application values or IDs.
- Backend teams needing human-readable encrypted values for demos, controlled workflows, or user-facing exports.
- Developers who prefer a compact Base64 encoding for normal production transport.

WKWCrypt **does not** replace application secrets management, transport security, access control, or password hashing.

## 2. Goals and non-goals

### 2.1 Goals

| ID | Requirement |
|---|---|
| G-01 | Securely encrypt arbitrary supported byte sequences. |
| G-02 | Restore plaintext exactly with the correct key or password. |
| G-03 | Support direct 32-byte secret keys and password-derived keys. |
| G-04 | Support lossless, versioned funny-word and Base64 encodings. |
| G-05 | Reject tampering, malformed payloads, and unsafe parameters. |
| G-06 | Work on macOS, Linux, and Windows without external services. |
| G-07 | Expose an idiomatic, small, testable Go API. |
| G-08 | Bound input sizes and resource consumption. |

### 2.2 Non-goals (MVP)

- Tiny, database-free, reversible nicknames such as `angry-potato`.
- User authentication or reversible storage of account passwords.
- File/stream encryption, multi-recipient envelopes, asymmetric encryption.
- Hosted key management, centralized storage, or synchronization.
- Automatic key rotation, rollback prevention, or replay prevention.
- Claims of FIPS validation, external audits, or post-quantum security.

## 3. User stories

1. **Raw key:** As a backend developer, I can encrypt and decrypt bytes using an application-managed 256-bit key.
2. **Password:** As a developer, I can use a passphrase when key management is impractical for an occasional operation.
3. **Funny words:** As a developer, I can select a readable output encoding that round-trips without losing data.
4. **Compact mode:** As a developer, I can choose Base64 URL-safe output without changing cryptographic semantics.
5. **Defense:** As a service owner, I can reject malformed or hostile payloads without uncontrolled CPU or memory use.
6. **Portability:** As a developer, I can encrypt on macOS and decrypt on Linux/Windows using the same secret.

## 4. Functional requirements

### FR-01: Authenticated raw-key encryption (P0)

- Use **XChaCha20-Poly1305** from a maintained Go cryptography package.
- Require an exactly 32-byte raw key; reject any other size.
- Generate a fresh cryptographically random 24-byte nonce for every encryption.
- Authenticate encryption metadata as well as ciphertext.
- Never log or embed the raw key in output.
- Return an error on randomness, encoding, or validation failure.
- Different encryptions of the same plaintext under the same key must normally have different outputs due to random nonces.

**Acceptance:** Decrypting valid ciphertext yields exact plaintext; wrong keys and modified ciphertext fail authentication; nonce generation uses `crypto/rand`.

### FR-02: Password encryption (P0)

- Derive the encryption key using **Argon2id**, with an independent random 16-byte salt per encryption.
- Initial parameters: **64 MiB memory, 3 iterations, parallelism 4, output 32 bytes**. These are defaults to validate with hardware benchmarks, not immutable security guarantees.
- Store salt and KDF parameters inside the authenticated envelope; never store the password.
- Reject empty passwords and unsupported / resource-exhausting KDF parameters before allocation.
- Bound concurrent Argon2id work; password mode is intended for low-volume workloads.
- Wrong password must fail with an authentication error; do not leak partially decrypted plaintext.

**Acceptance:** Valid password round-trips; wrong password fails; repeated encryption uses fresh salt and nonce; malicious KDF fields are rejected safely.

### FR-03: Lossless funny-word encoding (P0)

- Ship an immutable **v1 dictionary of exactly 2,048 unique ASCII words** (11 bits per word).
- Convert binary envelopes to word indices and back without changing any bytes.
- Encode the byte length explicitly so trailing padding cannot cause ambiguity; validate canonical zero padding.
- Restrict word characters and separators to an unambiguous grammar.
- Reject unknown words, invalid separators, noncanonical encodings, truncation, and excess length.
- Format textual output as `wkw1:words:<word>-<word>-...`.
- Document that a short plaintext produces dozens of words due to nonce, tag, and metadata overhead.

**Acceptance:** `DecodeWords(EncodeWords(b)) == b` for arbitrary supported byte arrays, including null bytes. The decoder rejects malformed/noncanonical input.

### FR-04: Compact Base64 encoding (P0)

- Use unpadded Base64 URL-safe encoding of the **same binary envelope**.
- Format textual output as `wkw1:b64:<base64url>`.
- The decoder automatically recognizes `words` and `b64` prefixes.
- Reject unknown encodings, noncanonical Base64, and malformed prefixes.

**Acceptance:** Both encodings can represent exactly the same envelope bytes. The selected encoding does not alter encryption strength.

### FR-05: Authenticated decryption (P0)

- Parse prefix and envelope within strict size limits.
- Check format version and key mode.
- Validate nonce, tag, salt, and KDF parameter lengths.
- Reconstruct the authenticated header and decrypt only after validation.
- Return plaintext only after successful AEAD authentication.
- Expose stable, nonsensitive error categories for invalid key, invalid payload, unsupported version, invalid encoding, unsafe KDF parameters, and authentication failure.

### FR-06: Associated data / context binding (P1)

- Allow callers to supply AAD (e.g. tenant identifier) to bind ciphertext to application context.
- Bind both header and user-supplied AAD unambiguously into AEAD authentication.
- AAD is **not encrypted** and must match exactly at decrypt time.
- Do not silently default to a different tenant or scope.

**Acceptance:** Ciphertext encrypted with `tenant:A` cannot be decrypted with `tenant:B` even with the same key.

### FR-07: Safe limits (P0)

| Setting | Proposed MVP default |
|---|---:|
| Max plaintext | 1 KiB |
| Recommended plaintext | ≤256 bytes |
| Max binary envelope | 2 KiB |
| Max encoded text | 32 KiB |
| Max Argon2id memory accepted at decryption | 128 MiB |
| Max Argon2id iterations accepted | 5 |
| Max Argon2id parallelism accepted | 4 |
| Max concurrent password operations per process | 2 |

These are conservative provisional product defaults, to be revisited after benchmark and security tests. Validate size limits **before** expensive decoding, allocations, or KDF execution. Avoid unbounded queues behind a concurrency limiter.

## 5. Public API (proposed, not yet implemented)

```go
// Raw-key mode: caller securely generates and stores a 32-byte key.
func EncryptWithKey(plaintext, key []byte, opts ...Option) (string, error)
func DecryptWithKey(ciphertext string, key []byte, opts ...Option) ([]byte, error)

// Password mode: substantially more expensive due to Argon2id.
func EncryptWithPassword(plaintext, password []byte, opts ...Option) (string, error)
func DecryptWithPassword(ciphertext string, password []byte, opts ...Option) ([]byte, error)

type Encoding string
const (
    EncodingWords  Encoding = "words"
    EncodingBase64 Encoding = "b64"
)

func WithEncoding(encoding Encoding) Option // encryption only
func WithAAD(aad []byte) Option
```

- Default encryption encoding: `EncodingWords`.
- Decryption auto-detects encoding; callers cannot override envelope metadata.
- Functions remain concurrency-safe; caller-supplied slices must not be modified while calls run.
- APIs must explicitly document allocation behavior and how application secrets are handled.
- Consider a configured `Cipher` instance if enforcing resource limits cleanly requires it; avoid global mutable configuration.

## 6. Non-functional requirements

### Security

- Authenticated encryption only; no homemade cipher.
- Unique secure randomness, authenticated header, strict parsing and bounds.
- Security documentation must distinguish confidentiality, integrity, password strength, and metadata exposure.
- See [SECURITY.md](SECURITY.md).

### Reliability / portability

- The same payload must decrypt on macOS ARM64, Linux AMD64, and Windows AMD64.
- Wordlist order and envelope serialization must remain stable across releases.
- Reject unsupported versions instead of guessing.

### Performance

These are **initial benchmark targets**, not measured results:

| Operation | Target on representative developer/server hardware |
|---|---:|
| Raw-key encrypt/decrypt, 128 B | <100 µs each |
| Word encode/decode, 128 B | <100 µs each |
| Password encrypt/decrypt | Aim for <500 ms each, subject to safe Argon2id parameters |

- Benchmark allocations and throughput separately for 16 B, 128 B, and 1 KiB inputs.
- Raw-key operations should be fast and have memory usage proportional to payload size.
- Password KDFs intentionally consume considerable memory and CPU; no unlimited parallelism.
- See [TEST_PLAN.md](TEST_PLAN.md).

## 7. Delivery scope and milestones

| Phase | Scope | Exit criterion |
|---|---|---|
| 1 | Raw-key AEAD, nonce handling, envelope | Correct authenticated binary round-trips |
| 2 | Argon2id, salts, bounded parameters/concurrency | Password mode passes negative and resource-limit tests |
| 3 | Immutable funny-word dictionary/codec | Arbitrary binary round-trip, canonical decoding, fuzz tests |
| 4 | Base64, public API, docs, AAD | Stable developer-facing interface and examples |
| 5 | Cross-platform CI, benchmarks, security review | All MVP P0 acceptance criteria met |

### Out-of-scope roadmap

CLI; alternate themed wordlists; short nicknames backed by durable encrypted storage; app-managed key IDs/rotation; streaming encryption; batch utilities; improved verbal/grammar formatting.

## 8. Release and success criteria

- All P0 requirements implemented and documented.
- Tests cover plaintext/empty/unicode/binary, incorrect secrets, malformed input, corrupted tags, and AAD mismatch.
- Fuzzing produces no unresolved panics; `go test -race ./...` passes.
- Deterministic compatibility vectors are checked on all supported operating systems.
- No plaintext or secrets are included in logs or error details.
- KDF resource limits are tested, including hostile input and concurrency.
- Benchmarks and limitations are published; no unverified security/audit claims.
- Dependencies and vulnerability status reviewed before release.

## 9. Open decisions before implementation

1. Final Go module path and repository owner.
2. Exact binary envelope layout, stable header/AAD framing, and error taxonomy.
3. Final frozen 2,048-word dictionary and rules for future dictionary versions.
4. Whether the resource-limited password API should use an explicit configured instance instead of package globals.
5. Supported minimum Go version and continuous-integration matrix.

See [TECHNICAL_DESIGN.md](TECHNICAL_DESIGN.md) for the proposed implementation contract.
