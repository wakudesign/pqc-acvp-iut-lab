import json
import unittest
from pathlib import Path

from pqc_acvp.backends.mldsa_native import MLDSANativeBackend
from pqc_acvp.mldsa import (
    MLDSABackendFailure,
    MLDSACapabilities,
    MLDSAErrorCode,
    MLDSAInvalidInput,
    MLDSAKeyGenSeed,
    MLDSAOperation,
    MLDSAParameterSet,
    MLDSASigningMode,
    MLDSASigningRandomness,
    MLDSAUnsupportedCapability,
    mldsa_parameter_metadata,
)


ROOT = Path(__file__).parents[2]
BRIDGE = ROOT / "build" / "mldsa-native" / "portable-multilevel" / "mldsa_native_bridge"
MANIFEST = ROOT / "evidence" / "build" / "mldsa-native-portable.json"


class MLDSANativeBackendTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BRIDGE.is_file() or not MANIFEST.is_file():
            raise unittest.SkipTest("mldsa-native portable build is unavailable")
        cls.backend = MLDSANativeBackend.from_build_manifest(BRIDGE, MANIFEST)

    def test_all_parameter_sets_keygen_sign_and_verify(self):
        for index, parameter_set in enumerate(MLDSAParameterSet, start=1):
            with self.subTest(parameter_set=parameter_set.value):
                pair = self.backend.keygen_deterministic(
                    parameter_set, MLDSAKeyGenSeed(bytes([index]) * 32)
                )
                sizes = mldsa_parameter_metadata(parameter_set).sizes
                self.assertEqual(len(pair.public_key), sizes.public_key)
                self.assertEqual(len(pair.secret_key), sizes.secret_key)

                deterministic = self.backend.sign_pure(
                    parameter_set,
                    pair.secret_key,
                    b"adapter contract message",
                    b"portfolio",
                    MLDSASigningRandomness.deterministic(),
                )
                repeated = self.backend.sign_pure(
                    parameter_set,
                    pair.secret_key,
                    b"adapter contract message",
                    b"portfolio",
                    MLDSASigningRandomness.deterministic(),
                )
                self.assertEqual(deterministic, repeated)
                self.assertTrue(
                    self.backend.verify_pure(
                        parameter_set,
                        pair.public_key,
                        b"adapter contract message",
                        b"portfolio",
                        deterministic,
                    ).valid
                )

                hedged = self.backend.sign_pure(
                    parameter_set,
                    pair.secret_key,
                    b"adapter contract message",
                    b"portfolio",
                    MLDSASigningRandomness.hedged(bytes([index + 32]) * 32),
                )
                self.assertNotEqual(hedged, deterministic)
                self.assertTrue(
                    self.backend.verify_pure(
                        parameter_set,
                        pair.public_key,
                        b"adapter contract message",
                        b"portfolio",
                        hedged,
                    ).valid
                )

    def test_context_is_part_of_signature_domain(self):
        pair = self.backend.keygen_deterministic(
            MLDSAParameterSet.ML_DSA_44, MLDSAKeyGenSeed(b"k" * 32)
        )
        signature = self.backend.sign_pure(
            MLDSAParameterSet.ML_DSA_44,
            pair.secret_key,
            b"message",
            b"context-a",
            MLDSASigningRandomness.deterministic(),
        )
        self.assertTrue(
            self.backend.verify_pure(
                MLDSAParameterSet.ML_DSA_44,
                pair.public_key,
                b"message",
                b"context-a",
                signature,
            ).valid
        )
        self.assertFalse(
            self.backend.verify_pure(
                MLDSAParameterSet.ML_DSA_44,
                pair.public_key,
                b"message",
                b"context-b",
                signature,
            ).valid
        )

    def test_same_length_modified_signature_is_normal_negative_result(self):
        pair = self.backend.keygen_deterministic(
            MLDSAParameterSet.ML_DSA_65, MLDSAKeyGenSeed(b"s" * 32)
        )
        signature = bytearray(
            self.backend.sign_pure(
                MLDSAParameterSet.ML_DSA_65,
                pair.secret_key,
                b"message",
                b"",
                MLDSASigningRandomness.deterministic(),
            )
        )
        signature[0] ^= 1
        result = self.backend.verify_pure(
            MLDSAParameterSet.ML_DSA_65,
            pair.public_key,
            b"message",
            b"",
            bytes(signature),
        )
        self.assertFalse(result.valid)

    def test_malformed_signature_is_invalid_input_not_negative_result(self):
        pair = self.backend.keygen_deterministic(
            MLDSAParameterSet.ML_DSA_44, MLDSAKeyGenSeed(b"m" * 32)
        )
        with self.assertRaises(MLDSAInvalidInput) as caught:
            self.backend.verify_pure(
                MLDSAParameterSet.ML_DSA_44,
                pair.public_key,
                b"message",
                b"",
                b"short",
            )
        self.assertEqual(caught.exception.code, MLDSAErrorCode.INVALID_INPUT_LENGTH)

    def test_maximum_context_and_message_are_supported(self):
        pair = self.backend.keygen_deterministic(
            MLDSAParameterSet.ML_DSA_44, MLDSAKeyGenSeed(b"b" * 32)
        )
        signature = self.backend.sign_pure(
            MLDSAParameterSet.ML_DSA_44,
            pair.secret_key,
            b"m" * 8192,
            b"c" * 255,
            MLDSASigningRandomness.hedged(b"r" * 32),
        )
        self.assertTrue(
            self.backend.verify_pure(
                MLDSAParameterSet.ML_DSA_44,
                pair.public_key,
                b"m" * 8192,
                b"c" * 255,
                signature,
            ).valid
        )

    def test_unsupported_capability_is_enforced_before_invocation(self):
        restricted = MLDSANativeBackend.from_build_manifest(BRIDGE, MANIFEST)
        restricted.capabilities = MLDSACapabilities(
            frozenset({MLDSAParameterSet.ML_DSA_44}),
            frozenset({MLDSAOperation.SIGGEN}),
            frozenset({MLDSASigningMode.DETERMINISTIC}),
        )
        with self.assertRaises(MLDSAUnsupportedCapability):
            restricted.sign_pure(
                MLDSAParameterSet.ML_DSA_44,
                b"x" * 2560,
                b"message",
                b"",
                MLDSASigningRandomness.hedged(b"r" * 32),
            )

    def test_manifest_metadata_and_bridge_hash_are_enforced(self):
        data = json.loads(MANIFEST.read_text(encoding="utf-8"))
        self.assertTrue(data["bridgeZeroizeSelfTestPassed"])
        self.assertTrue(data["repeatBuildMatched"])
        self.assertEqual(self.backend.metadata.name, "mldsa-native")
        self.assertEqual(self.backend.metadata.version, "v1.0.0-beta2")
        self.assertEqual(
            self.backend.metadata.commit,
            "9b0ee84f4cf399043eca59eca4e5f8531ca1d61b",
        )
        with self.assertRaises(MLDSABackendFailure):
            MLDSANativeBackend.from_build_manifest(
                ROOT / "does-not-exist", MANIFEST
            )


if __name__ == "__main__":
    unittest.main()
