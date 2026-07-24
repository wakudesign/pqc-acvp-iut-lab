# Backend contracts

## ML-KEM v1

The first common contract is a typed Python boundary between ACVP orchestration and native cryptographic backends. It does not implement ML-KEM mathematics.

### Parameter sets and sizes

| Parameter set | ek | dk | ciphertext | shared secret | d | z | m |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| ML-KEM-512 | 800 | 1632 | 768 | 32 | 32 | 32 | 32 |
| ML-KEM-768 | 1184 | 2400 | 1088 | 32 | 32 | 32 | 32 |
| ML-KEM-1024 | 1568 | 3168 | 1568 | 32 | 32 | 32 | 32 |

All sizes are bytes. The values follow FIPS 203 Table 3 and the internal-function inputs in Algorithms 16 and 17.

### Validation-only deterministic API

```text
keygen_deterministic(parameter_set, KeyGenEntropy(d, z)) -> (ek, dk)
encaps_deterministic(parameter_set, ek, EncapsulationEntropy(m)) -> (ciphertext, shared_secret)
decaps(parameter_set, dk, ciphertext) -> shared_secret
check_encapsulation_key(parameter_set, ek) -> KeyCheckResult
check_decapsulation_key(parameter_set, dk) -> KeyCheckResult
```

The ACVP JSON field is named `m`; the contract uses that name instead of a vague RNG callback. `d`, `z`, and `m` are exactly 32 bytes.

### Decapsulation semantics

- A ciphertext with the wrong type or length is invalid input and must not reach the backend.
- A ciphertext with the correct length but modified content is a normal decapsulation case. The backend follows implicit rejection and returns a 32-byte shared secret.
- The API does not return a `ciphertextValid` flag and must not raise an error solely because implicit rejection occurred.
- A native crash, missing symbol or impossible output length is a backend failure.

This separation avoids converting ciphertext validity into an oracle at the common API boundary.

### Key checks

- Encapsulation key check follows FIPS 203 Section 7.2: byte length and canonical modulus encoding.
- Decapsulation key check follows FIPS 203 Section 7.3: byte length and the embedded `H(ek)` consistency check.
- An invalid candidate key produces `KeyCheckResult(valid=False, failure=...)`; it is expected ACVP test data, not a backend exception.
- A non-byte programming-language value is an invalid API input and does raise `InvalidInput`.

The ACVP serializer only emits `testPassed`; the internal failure reason exists for diagnostics and tests and must not include key material.

### Error taxonomy

| Error code | Meaning |
| --- | --- |
| `invalidParameterSet` | Unknown ML-KEM parameter-set name |
| `invalidInputType` | API value is not immutable bytes |
| `invalidInputLength` | Key, seed, ciphertext or shared-secret length is wrong |
| `invalidKeyEncoding` | A checked key has a malformed encoding outside key-check test semantics |
| `unsupportedCapability` | Backend does not implement the requested parameter set / operation |
| `backendFailure` | Native backend invocation or output contract failed |
| `rngFailure` | Production backend could not obtain required randomness |

Structured errors contain only code, operation, parameter set and a fixed message. They must never embed input keys, ciphertexts, seeds or command lines.

### ACVP entropy versus production RNG

`MLKEMACVPTestBackend` exposes deterministic internal-function inputs solely for validation. `MLKEMProductionBackend` provides `keygen(parameter_set)` and `encaps(parameter_set, ek)` without caller-supplied entropy.

An application must not receive an ACVP backend object through dependency injection. Production randomness is generated inside the cryptographic module using its approved RNG path. FIPS 203 explicitly restricts controlled access to the internal derandomized functions to testing purposes.

## Normative references

- NIST FIPS 203, final: <https://doi.org/10.6028/NIST.FIPS.203>
- ACVP ML-KEM JSON specification: <https://pages.nist.gov/ACVP/draft-celi-acvp-ml-kem.html>

References and the published FIPS 203 errata notice were checked on 2026-07-15. Backend conformance must be re-reviewed when NIST publishes a corrected revision.

## ML-DSA v1

ML-DSA uses a separate signature contract; it does not reuse ML-KEM key or operation abstractions.

### Parameter sets and sizes

| Parameter set | public key | secret key | signature | seed | rnd |
| --- | ---: | ---: | ---: | ---: | ---: |
| ML-DSA-44 | 1312 | 2560 | 2420 | 32 | 32 |
| ML-DSA-65 | 1952 | 4032 | 3309 | 32 | 32 |
| ML-DSA-87 | 2592 | 4896 | 4627 | 32 | 32 |

All sizes are bytes. The v1 validation-only contract is:

```text
keygen_deterministic(parameter_set, MLDSAKeyGenSeed(seed)) -> (public_key, secret_key)
sign_pure(parameter_set, secret_key, message, context, signing_randomness) -> signature
verify_pure(parameter_set, public_key, message, context, signature) -> VerificationResult
```

`MLDSASigningRandomness.deterministic()` supplies the FIPS 204 all-zero `rnd`. `MLDSASigningRandomness.hedged(rnd)` accepts the 32-byte randomness supplied by an ACVP test vector. This caller-controlled input is validation-only and must not become the default production signing API.

The v1 contract accepts messages from 1 to 8192 bytes and context strings from 0 to 255 bytes. It supports pure ML-DSA over the external interface only. Pre-hash, internal interface and external `mu` are rejected capabilities until a later decision record expands the scope.

### Verification semantics

- A correctly sized but cryptographically invalid signature produces `MLDSAVerificationResult(valid=False)`.
- A signature, key, message or context with an invalid type or length is invalid input and does not reach native code.
- A missing bridge, native failure, timeout or malformed bridge response is a backend failure.
- Structured errors contain fixed metadata only and never include seed, rnd, keys, messages, context or signatures.

The bridge sends secrets through standard input rather than process arguments, uses explicit internal seed/rnd functions, provides a fail-closed `randombytes` symbol and clears its working buffers before exit.

### Metadata boundary

Each backend exposes FIPS 204 key and signature sizes, security category, supported operations, signing modes and pure/external scope. Build metadata binds the adapter to the exact bridge hash, dependency release/commit, compiler, flags and target.

### Normative references

- NIST FIPS 204, final: <https://doi.org/10.6028/NIST.FIPS.204>
- ACVP ML-DSA JSON specification: <https://pages.nist.gov/ACVP/draft-celi-acvp-ml-dsa.html>
