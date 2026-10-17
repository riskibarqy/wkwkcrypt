# WKWCrypt — Test Plan and Acceptance Checklist

**Status:** Draft v0.1.0  
**Primary command:** `go test ./...`

## 1. Test strategy

Use layered testing: unit tests for crypto wrappers, KDF, serialization, and codecs; integration tests for public round-trips; security-focused negative cases; fuzz/property tests for parsers; cross-platform format vectors; and benchmarks for throughput and allocation cost.

## 2. Functional test matrix

| ID | Test | Expected |
|---|---|---|
| C-01 | Raw-key encrypt/decrypt normal bytes | Exact round-trip |
| C-02 | Raw-key encrypt/decrypt zero-length bytes | Exact round-trip |
| C-03 | Raw-key encrypt/decrypt Unicode UTF-8 | Exact byte round-trip |
| C-04 | Raw-key encrypt/decrypt arbitrary binary including null bytes | Exact byte round-trip |
| C-05 | Raw-key short/long invalid key lengths | Typed validation error |
| C-06 | Wrong raw key | Authentication failure; no plaintext returned |
| C-07 | Same key + plaintext encrypted twice | Distinct nonce/output with overwhelming probability |
| P-01 | Password encrypt/decrypt | Exact round-trip |
| P-02 | Wrong password | Authentication failure |
| P-03 | Empty password | Validation error |
| P-04 | Repeated password encryption | Fresh salt and nonce |
| P-05 | Excessive Argon2id memory/time/parallelism in envelope | Rejected before KDF allocation |
| P-06 | Password concurrent request cap exceeded | Predictable bounded behavior, no unbounded queue |
| W-01 | Word encode/decode empty and arbitrary bytes | Exact round-trip |
| W-02 | Unknown word | Decode error |
| W-03 | Extra/missing word | Decode error |
| W-04 | Non-zero trailing padding | Decode error |
| W-05 | Encoded length inconsistent with word count | Decode error |
| W-06 | Changed dictionary order within same format version | Compatibility test failure |
| B-01 | Base64 encode/decode arbitrary envelope | Exact round-trip |
| B-02 | Noncanonical or malformed Base64 | Decode error |
| E-01 | Unknown `wkw` version | Unsupported-version error |
| E-02 | Unknown mode/suite/KDF | Error; no downgrade |
| E-03 | Truncated nonce/tag/header | Invalid-payload error |
| E-04 | Tamper with authenticated header | Authentication failure or strict validation error |
| E-05 | Tamper with encrypted body/tag | Authentication failure |
| A-01 | Correct AAD | Round-trip |
| A-02 | Incorrect/missing AAD | Authentication failure |
| L-01 | Plaintext > max | Error before encryption |
| L-02 | Encoded input > max | Error before expensive parsing |
| L-03 | Envelope length > max | Error before large allocation |
| X-01 | Encode on macOS, decrypt on Linux/Windows | Identical plaintext |

## 3. Property-based and fuzz testing

For arbitrary valid byte sequences `b`:

```go
DecodeWords(EncodeWords(b)) == b
DecodeBase64(EncodeBase64(b)) == b
DecryptWithKey(EncryptWithKey(b, k), k) == b
```

Add fuzz entry points for:

- Binary envelope parser.
- Word decoder and canonical padding checks.
- Base64 text parser.
- Version and mode parsing.
- KDF-parameter decoder and bounds.

A fuzz test should confirm inputs do not cause unexpected panics, allocation bombs, or hangs within chosen budgets.

## 4. Deterministic compatibility vectors

Include checked-in vectors (for development/testing only) covering:

- v1 raw-key encryption with fixed **test-only** key and nonce.
- v1 password mode with fixed **test-only** password, salt, and nonce.
- Equivalent funny-word and Base64 representations of the same binary envelope.
- AAD-authenticated messages.
- Invalid/tampered fixtures.

Production entry points must still generate random nonces and salts. Test-only controls must not expose an easy way for callers to set fixed nonces in production.

## 5. Cross-platform CI matrix

- macOS arm64.
- Linux amd64.
- Windows amd64.
- Go version matrix: choose supported minimum and latest stable before release.

Use the same format vectors across all platforms. Verify dictionary ordering does not depend on locale, OS, filesystem ordering, or Go map iteration.

## 6. Benchmark plan

```bash
go test ./...
go test -race ./...
go test -bench=. -benchmem ./...
```

Measure at minimum:

| Area | Sizes / cases | Metrics |
|---|---|---|
| AEAD raw-key | 16 B, 128 B, 1 KiB | ns/op, B/op, allocs/op |
| Word codec | 16 B, 128 B, 1 KiB binary | ns/op, B/op, allocs/op, output length |
| Base64 codec | Same sizes | ns/op, B/op, allocs/op, output length |
| Argon2id | Default and allowed alternative parameters | latency, peak memory, concurrency effect |
| End-to-end | Both modes + both encodings | p50/p95/p99 latency, throughput |

### Provisional targets

- Raw-key encrypt/decrypt 128-byte payload: <100 µs each on representative hardware.
- Word encode/decode 128-byte payload: <100 µs each.
- Password operations: <500 ms desirable **without reducing Argon2id safety parameters merely to meet the target**.
- Concurrent password work must respect configured capacity and stay within predictable memory budgets.

These targets are unverified until measured. Record CPU, Go version, dependency versions, memory setting, input size, and run count with every published number.

## 7. Definition of done

- [ ] All P0 tests in the functional matrix pass.
- [ ] Cross-platform compatibility vectors are stable.
- [ ] No unexpected failures under the Go race detector.
- [ ] Fuzz suites have no unresolved crashes or hangs.
- [ ] KDF limit and concurrency tests show bounded resource behavior.
- [ ] Benchmarks are recorded and interpreted, not guessed.
- [ ] No plaintext/secret exposure via errors or logs.
- [ ] Security review items from [SECURITY.md](SECURITY.md) are complete.
- [ ] Public API docs and examples match implementation.
