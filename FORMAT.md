# WKWCrypt v1 Envelope Contract

This document freezes the repository's `wkw1` binary envelope and its Base64 and word representations. Compatibility vectors in `testdata/v1_vectors.json` and `internal/codec/words_test.go` enforce this contract. It remains an experimental pre-release contract until the project completes its security and release review.

## Binary Envelope

All integers are unsigned big-endian. The binary envelope is:

```text
magic(3) | version(1) | mode(1) | suite(1) | kdf(1) |
  [memory_kib(4) | iterations(4) | parallelism(1) | salt(16)] |
  nonce(24) | ciphertext_and_tag(variable, at least 16)
```

| Field | Value |
|---|---|
| `magic` | ASCII `WKW` |
| `version` | `1` |
| raw-key `mode` | `1` |
| password `mode` | `2` |
| `suite` | `1` for XChaCha20-Poly1305 |
| raw-key `kdf` | `0` |
| password `kdf` | `1` for Argon2id |
| password `memory_kib` | `uint32` |
| password `iterations` | `uint32` |
| password `parallelism` | `uint8` |
| password `salt` | 16 bytes |
| `nonce` | 24 bytes |

Raw-key headers are 31 bytes. Password headers are 56 bytes. The entire envelope must be at most 2 KiB and must contain an AEAD tag.

## Authentication

The associated data supplied to XChaCha20-Poly1305 is exactly:

```text
uint32(len(header)) | header | uint32(len(external_aad)) | external_aad
```

The header includes all fields through `nonce`. External AAD is authenticated but not encrypted. Any header or AAD change must cause authentication failure.

## Text Representation

Two canonical representations are supported:

```text
wkw1:b64:<base64url(binary-envelope)>
wkw1:words:<word>-<word>-...
```

Base64 uses unpadded URL-safe encoding. The word representation prepends the binary-envelope length as a big-endian `uint32`, groups that byte stream into 11-bit indices (zero-padding only the final group), and maps each index to the immutable BIP-0039 English word list. It uses the list at Bitcoin BIPs commit `927b6de9915c9262615a6399de51b200f81e5aa4`, with SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. This is an encoding only, not a BIP-0039 mnemonic or wallet backup.

The parser rejects unknown prefixes, Base64 padding or noncanonical Base64, unknown or malformed words, nonzero word padding, empty payloads, encoded text larger than 32 KiB, malformed envelopes, and unsupported modes/suites/KDFs.

## Stable Error Categories

Public APIs return these sentinel errors for non-secret conditions:

| Condition | Error |
|---|---|
| Key is not exactly 32 bytes | `ErrInvalidKey` |
| Password is empty | `ErrInvalidPassword` |
| Malformed envelope or incorrect mode for API | `ErrInvalidPayload` |
| Invalid or noncanonical text representation | `ErrInvalidEncoding` |
| Magic is valid but version is unknown | `ErrUnsupportedVersion` |
| Unsupported mode, suite, or KDF | `ErrUnsupported` |
| Password KDF parameters are zero or exceed limits | `ErrUnsafeParameters` |
| Password KDF capacity is exhausted | `ErrBusy` |
| Wrong valid key/password, altered ciphertext, header, or AAD | `ErrAuthentication` |
| Plaintext exceeds 1 KiB | `ErrPlaintextTooLarge` |

Errors must not include plaintext, keys, passwords, salts, ciphertext, or unauthenticated field values.

## Compatibility Vectors

`testdata/v1_vectors.json` contains test-only raw-key and password fixtures with fixed keys, passwords, salts, and nonces. Production APIs must always generate fresh random nonces and salts; this contract does not expose caller-controlled production nonce or salt settings.
