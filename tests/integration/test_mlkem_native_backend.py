import json
import unittest
from pathlib import Path

from pqc_acvp.backends.mlkem_native import MLKEMNativeBackend
from pqc_acvp.mlkem import (
    EncapsulationEntropy,
    ErrorCode,
    InvalidInput,
    KeyCheckFailure,
    KeyGenEntropy,
    MLKEMCapabilities,
    MLKEMOperation,
    MLKEMParameterSet,
    UnsupportedCapability,
    parameter_metadata,
)


ROOT = Path(__file__).parents[2]


class MLKEMNativeBackendContract:
    bridge: Path
    manifest: Path
    native_arithmetic: bool
    native_fips202: bool

    @classmethod
    def setUpClass(cls):
        if not cls.bridge.is_file() or not cls.manifest.is_file():
            raise unittest.SkipTest(f"missing build profile: {cls.manifest.name}")
        cls.backend = MLKEMNativeBackend.from_build_manifest(cls.bridge, cls.manifest)

    def test_all_parameter_sets_support_deterministic_round_trip(self):
        for index, parameter_set in enumerate(MLKEMParameterSet, start=1):
            with self.subTest(parameter_set=parameter_set.value):
                pair = self.backend.keygen_deterministic(
                    parameter_set,
                    KeyGenEntropy(bytes([index]) * 32, bytes([index + 16]) * 32),
                )
                self.assertTrue(
                    self.backend.check_encapsulation_key(
                        parameter_set, pair.encapsulation_key
                    ).valid
                )
                self.assertTrue(
                    self.backend.check_decapsulation_key(
                        parameter_set, pair.decapsulation_key
                    ).valid
                )
                encapsulated = self.backend.encaps_deterministic(
                    parameter_set,
                    pair.encapsulation_key,
                    EncapsulationEntropy(bytes([index + 32]) * 32),
                )
                self.assertEqual(
                    self.backend.decaps(
                        parameter_set,
                        pair.decapsulation_key,
                        encapsulated.ciphertext,
                    ),
                    encapsulated.shared_secret,
                )

                modified = bytearray(encapsulated.ciphertext)
                modified[0] ^= 1
                rejected_secret = self.backend.decaps(
                    parameter_set, pair.decapsulation_key, bytes(modified)
                )
                self.assertEqual(len(rejected_secret), 32)
                self.assertNotEqual(rejected_secret, encapsulated.shared_secret)

    def test_upstream_key_checks_map_to_typed_results(self):
        parameter_set = MLKEMParameterSet.ML_KEM_768
        pair = self.backend.keygen_deterministic(
            parameter_set, KeyGenEntropy(b"d" * 32, b"z" * 32)
        )
        invalid_pk = bytearray(pair.encapsulation_key)
        invalid_pk[:3] = b"\xff\xff\xff"
        pk_result = self.backend.check_encapsulation_key(
            parameter_set, bytes(invalid_pk)
        )
        self.assertFalse(pk_result.valid)
        self.assertIs(pk_result.failure, KeyCheckFailure.NON_CANONICAL_ENCODING)

        invalid_sk = bytearray(pair.decapsulation_key)
        hash_offset = 768 * parameter_metadata(parameter_set).module_rank_k + 32
        invalid_sk[hash_offset] ^= 1
        sk_result = self.backend.check_decapsulation_key(
            parameter_set, bytes(invalid_sk)
        )
        self.assertFalse(sk_result.valid)
        self.assertIs(sk_result.failure, KeyCheckFailure.HASH_MISMATCH)

    def test_wrong_key_lengths_are_typed_and_not_sent_to_native_code(self):
        pk_result = self.backend.check_encapsulation_key(
            MLKEMParameterSet.ML_KEM_512, b"short"
        )
        sk_result = self.backend.check_decapsulation_key(
            MLKEMParameterSet.ML_KEM_512, b"short"
        )
        self.assertIs(pk_result.failure, KeyCheckFailure.INVALID_LENGTH)
        self.assertIs(sk_result.failure, KeyCheckFailure.INVALID_LENGTH)

        with self.assertRaises(InvalidInput) as caught:
            self.backend.encaps_deterministic(
                MLKEMParameterSet.ML_KEM_512,
                b"short",
                EncapsulationEntropy(b"m" * 32),
            )
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_INPUT_LENGTH)

    def test_invalid_decapsulation_key_and_ciphertext_sizes_are_typed(self):
        parameter_set = MLKEMParameterSet.ML_KEM_512
        pair = self.backend.keygen_deterministic(
            parameter_set, KeyGenEntropy(b"a" * 32, b"b" * 32)
        )
        encapsulated = self.backend.encaps_deterministic(
            parameter_set,
            pair.encapsulation_key,
            EncapsulationEntropy(b"c" * 32),
        )
        with self.assertRaises(InvalidInput) as caught:
            self.backend.decaps(
                parameter_set,
                pair.decapsulation_key,
                encapsulated.ciphertext[:-1],
            )
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_INPUT_LENGTH)

        invalid_key = bytearray(pair.decapsulation_key)
        invalid_key[1568] ^= 1
        with self.assertRaises(InvalidInput) as caught:
            self.backend.decaps(
                parameter_set, bytes(invalid_key), encapsulated.ciphertext
            )
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_KEY_ENCODING)

    def test_unsupported_capability_is_enforced_before_native_invocation(self):
        restricted = MLKEMNativeBackend.from_build_manifest(self.bridge, self.manifest)
        restricted.capabilities = MLKEMCapabilities(
            frozenset({MLKEMParameterSet.ML_KEM_512}),
            frozenset({MLKEMOperation.DECAPS}),
        )
        with self.assertRaises(UnsupportedCapability) as caught:
            restricted.keygen_deterministic(
                MLKEMParameterSet.ML_KEM_512,
                KeyGenEntropy(b"d" * 32, b"z" * 32),
            )
        self.assertEqual(caught.exception.code, ErrorCode.UNSUPPORTED_CAPABILITY)

    def test_metadata_and_zeroize_evidence_are_bound_to_bridge_hash(self):
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        self.assertTrue(manifest["bridgeZeroizeSelfTestPassed"])
        self.assertTrue(manifest["repeatBuildMatched"])
        self.assertEqual(self.backend.metadata.name, "mlkem-native")
        self.assertEqual(self.backend.metadata.version, "v1.2.0")
        self.assertEqual(
            self.backend.metadata.commit,
            "0ba906cb14b1c241476134d7403a811b382ca498",
        )
        self.assertIn(
            f"MLK_CONFIG_USE_NATIVE_BACKEND_ARITH={int(self.native_arithmetic)}",
            self.backend.metadata.flags,
        )
        self.assertIn(
            f"MLK_CONFIG_USE_NATIVE_BACKEND_FIPS202={int(self.native_fips202)}",
            self.backend.metadata.flags,
        )


class MLKEMNativePortableBackendTests(MLKEMNativeBackendContract, unittest.TestCase):
    bridge = ROOT / "build" / "mlkem-native" / "portable-multilevel" / "mlkem_native_bridge"
    manifest = ROOT / "evidence" / "build" / "mlkem-native-portable.json"
    native_arithmetic = False
    native_fips202 = False


class MLKEMNativeAArch64BackendTests(MLKEMNativeBackendContract, unittest.TestCase):
    bridge = (
        ROOT
        / "build"
        / "mlkem-native"
        / "aarch64-native-multilevel"
        / "mlkem_native_bridge"
    )
    manifest = ROOT / "evidence" / "build" / "mlkem-native-aarch64.json"
    native_arithmetic = True
    native_fips202 = True


if __name__ == "__main__":
    unittest.main()
