# WKWCrypt — Security Requirements and Threat Model

**Status:** Draft for v0.1.0. Not an independent security audit.

## Security promise

WKWCrypt aims to provide authenticated confidentiality and integrity for small encrypted values **when the caller protects the key or passphrase**. Funny names are only a lossless encoding of ciphertext; their apparent memorability must never be interpreted as cryptographic strength.

## Assumptions

- The encryption host, Go runtime, and dependency supply chain are trustworthy.
- Callers manage 32-byte raw keys securely or choose strong passphrases.
- The attacker may access, replace, truncate, replay, or submit arbitrary encrypted strings.
- No database or network service is required by the library.
- Application context (tenant, subject, purpose) may need external AAD to prevent cross-context substitution.

## Threats and required responses

| Threat | Required mitigation | Limitations |
|---|---|---|
| Ciphertext disclosure | XChaCha20-Poly1305 with secret 32-byte key | Leaked keys defeat confidentiality |
| Ciphertext modification | AEAD authentication of ciphertext and header | Does not detect deletion or rollback to old valid ciphertext |
| Nonce misuse | Fresh random 24-byte nonce from `crypto/rand` | Must not deliberately reuse a nonce with same key |
| Password guessing | Argon2id with per-message random salt and documented cost | Weak passwords remain guessable offline |
| Crafted KDF cost values | Check maximum memory/time/threads *before* calling Argon2id | Per-process concurrency must also be bounded |
| Malformed word/Base64 inputs | Strict parser, canonical forms, input bounds, fuzz testing | Very large volumes still need application rate limiting |
| Header manipulation | Authenticate serialized header using AEAD AAD | Validate version and supported suite before decryption |
| Cross-tenant ciphertext reuse | Caller-supplied contextual AAD | Caller must consistently set correct AAD |
| Log exposure | Do not log plaintext, secrets, or unredacted ciphertext without a clear need | Application logging is outside the library's control |
| Ciphertext replay | Not in scope for the library | Requires application state and replay/rollback controls |

## Key management

### Raw-key mode

- Accept exactly 32 bytes of cryptographically generated key material.
- Do not derive keys from timestamps, IDs, hashes of public fields, or `math/rand`.
- Do not commit keys to source control or put them in logs.
- Supply keys from an application secret manager or secure deployment mechanism.
- The raw key is **not** embedded in the encrypted envelope.
- v0.1.0 does not implement key rotation or key identifiers; design the application to track which key encrypted each record.

### Password mode

- Salt is public and stored with the ciphertext. **A salt cannot decrypt data.**
- The passphrase is the secret; Argon2id derives the actual encryption key.
- Generate a fresh 16-byte salt for each encryption.
- Initial Argon2id cost: 64 MiB, 3 passes, parallelism 4. Benchmark before deploying.
- Enforce strict upper bounds on attacker-controlled KDF parameters when decrypting.
- Limit concurrent KDF operations to avoid memory exhaustion.
- Prefer raw-key mode for high-throughput backend services.
- Do not use reversible encryption for stored user-login passwords: use password hashing instead.

## Authenticated envelope

- Use a fixed versioned envelope format.
- Authenticate every field that influences cryptographic interpretation, including version, mode, suite, nonce, salt, and KDF parameters.
- Bind caller-supplied AAD with unambiguous length framing.
- Reject unknown cryptographic suites rather than downgrading or guessing.
- Verify AEAD tag before returning any plaintext.
- Surface a generic authentication failure for wrong keys/passwords and modified ciphertext.

## Do not do these things

- Do not shorten an encrypted payload by truncating its words.
- Do not substitute an HMAC-based alias for reversible encryption.
- Do not implement a bespoke encryption algorithm or derive the key from a wordlist.
- Do not reuse a constant nonce or salt.
- Do not disable authentication to improve speed.
- Do not silently accept partially parsed words or ignore invalid padding.
- Do not make unverified claims of audited, FIPS, or post-quantum security.

## Security validation gate

A release must meet all of the following:

1. Known-answer or deterministic interoperability vectors for envelope/codec and AEAD behavior.
2. Negative tests for wrong keys, passwords, AAD, damaged tags, and malformed headers.
3. Property and fuzz tests for binary parsing and both codecs.
4. Bound tests for oversized ciphertext and hostile Argon2id parameters.
5. Go race detection for public APIs and password concurrency controls.
6. Review of transitive dependencies and published vulnerabilities.
7. Documentation of unresolved risks; no production-grade claims until review is complete.

## Disclosure process (to configure at repository launch)

Add a private reporting channel (for example GitHub Security Advisories) and a responsible disclosure policy before public launch. Do not ask researchers to publish exploitable issues in public GitHub issues.

## References

- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- RFC 9106 Argon2: https://www.rfc-editor.org/rfc/rfc9106
- XChaCha20-Poly1305 Go documentation: https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
