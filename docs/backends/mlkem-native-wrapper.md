# mlkem-native ACVP wrapper

## Ownership and boundary

The cryptographic implementation is upstream mlkem-native v1.2.0. This repository owns only the Python backend adapter, the one-shot C bridge, build integration, tests and evidence. The bridge calls public upstream APIs and does not copy or modify ML-KEM arithmetic.

This wrapper implements `MLKEMACVPTestBackend`; it is deliberately not a `MLKEMProductionBackend`.

## API mapping

| Common contract | Upstream public API |
| --- | --- |
| deterministic key generation | `mlkem{512,768,1024}_keypair_derand` |
| deterministic encapsulation | `mlkem{512,768,1024}_enc_derand` |
| decapsulation / implicit rejection | `mlkem{512,768,1024}_dec` |
| encapsulation-key check | `mlkem{512,768,1024}_check_pk` |
| decapsulation-key check | `mlkem{512,768,1024}_check_sk` |

The adapter performs type and length checks before native invocation. A same-length modified ciphertext is sent to `dec` and returns a 32-byte implicit-rejection secret without exposing a validity bit. Invalid key candidates from `check_pk` and `check_sk` become typed `KeyCheckResult` values rather than backend failures.

## Process protocol

The Python adapter starts one bridge process per operation. Only the operation and non-secret parameter level appear in process arguments. Hex-encoded keys, entropy, ciphertexts and messages are sent through stdin; native results return through stdout. The bridge accepts a fixed field count and fixed lengths for every operation and emits only fixed key names.

A one-shot process was selected over `ctypes` so native sensitive buffers do not remain inside the long-running Python process and no shared-library ABI becomes part of the first backend contract. Process creation overhead is acceptable for validation tooling and can be revisited only with benchmark evidence.

## Sensitive-buffer clearing

The clearing strategy has three layers:

1. Upstream mlkem-native zeroizes intermediate stack buffers using its default `mlk_zeroize` implementation (memset plus compiler barrier on this target).
2. The bridge clears all input, output, entropy and hex-line arrays through a volatile-byte zeroization loop on every normal cleanup path.
3. The bridge is a short-lived process, so its address space is destroyed after each operation.

The build executes `mlkem_native_bridge --self-test-zeroize`, binds the bridge source and binary hashes into the manifest, and integration tests exercise every operation and all three parameter sets.

Limitations are explicit: Python immutable `bytes` and temporary hex strings cannot be reliably overwritten, and the OS, pipes, compiler or runtime may create additional copies. This is an ACVP validation interface, not a claim of complete memory remanence protection. Secrets are not placed in command-line arguments or structured error messages.

The library's optional `randombytes` symbol is satisfied by a fail-closed bridge function that clears the requested output and returns failure. Production randomized key generation or encapsulation is intentionally unavailable through this bridge.

## Backend metadata

`MLKEMNativeBackend.from_build_manifest()` verifies the bridge SHA-256 before use, then loads release, commit, target, compiler, flags and native-feature settings from the selected portable or AArch64-native build manifest. A rebuilt or replaced bridge cannot silently retain old provenance.
