import unittest

from pqc_acvp.mldsa import (
    MLDSABackendFailure,
    MLDSACapabilities,
    MLDSAErrorCode,
    MLDSAInvalidInput,
    MLDSAKeyGenSeed,
    MLDSAKeyPair,
    MLDSAOperation,
    MLDSAParameterSet,
    MLDSASigningMode,
    MLDSASigningRandomness,
    MLDSAUnsupportedCapability,
    mldsa_parameter_metadata,
    validate_key_pair_output,
    validate_message_and_context,
    validate_signature_output,
    validate_verification_inputs,
)


class MLDSAParameterTests(unittest.TestCase):
    def test_parameter_metadata_matches_fips_204_sizes(self):
        expected = {
            MLDSAParameterSet.ML_DSA_44: (1312, 2560, 2420, 2),
            MLDSAParameterSet.ML_DSA_65: (1952, 4032, 3309, 3),
            MLDSAParameterSet.ML_DSA_87: (2592, 4896, 4627, 5),
        }
        for parameter_set, values in expected.items():
            with self.subTest(parameter_set=parameter_set.value):
                metadata = mldsa_parameter_metadata(parameter_set)
                self.assertEqual(
                    (
                        metadata.sizes.public_key,
                        metadata.sizes.secret_key,
                        metadata.sizes.signature,
                        metadata.security_category,
                    ),
                    values,
                )

    def test_unknown_parameter_set_is_typed(self):
        with self.assertRaises(MLDSAInvalidInput) as caught:
            MLDSAParameterSet.parse("Dilithium3")
        self.assertEqual(caught.exception.code, MLDSAErrorCode.INVALID_PARAMETER_SET)


class MLDSARandomnessTests(unittest.TestCase):
    def test_keygen_seed_is_exactly_32_bytes(self):
        self.assertEqual(MLDSAKeyGenSeed(b"s" * 32).seed, b"s" * 32)
        with self.assertRaises(MLDSAInvalidInput):
            MLDSAKeyGenSeed(b"s" * 31)

    def test_deterministic_randomness_is_all_zero(self):
        randomness = MLDSASigningRandomness.deterministic()
        self.assertIs(randomness.mode, MLDSASigningMode.DETERMINISTIC)
        self.assertEqual(randomness.rnd, bytes(32))

    def test_nonzero_deterministic_rnd_is_rejected(self):
        with self.assertRaises(MLDSAInvalidInput) as caught:
            MLDSASigningRandomness(
                MLDSASigningMode.DETERMINISTIC, b"r" * 32
            )
        self.assertEqual(
            caught.exception.code, MLDSAErrorCode.INVALID_SIGNING_RANDOMNESS
        )

    def test_hedged_rnd_is_exactly_32_bytes(self):
        self.assertEqual(
            MLDSASigningRandomness.hedged(b"r" * 32).rnd, b"r" * 32
        )
        with self.assertRaises(MLDSAInvalidInput):
            MLDSASigningRandomness.hedged(b"r" * 33)


class MLDSAInputBoundaryTests(unittest.TestCase):
    def test_message_and_context_boundaries(self):
        validate_message_and_context(b"m", b"")
        validate_message_and_context(b"m" * 8192, b"c" * 255)
        for message, context in ((b"", b""), (b"m" * 8193, b""), (b"m", b"c" * 256)):
            with self.subTest(message_length=len(message), context_length=len(context)):
                with self.assertRaises(MLDSAInvalidInput):
                    validate_message_and_context(message, context)

    def test_mutable_values_are_rejected(self):
        with self.assertRaises(MLDSAInvalidInput) as caught:
            validate_message_and_context(bytearray(b"m"), b"")  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, MLDSAErrorCode.INVALID_INPUT_TYPE)

    def test_backend_output_size_failure_is_not_invalid_signature(self):
        with self.assertRaises(MLDSABackendFailure):
            validate_key_pair_output(
                MLDSAParameterSet.ML_DSA_44,
                MLDSAKeyPair(b"p" * 1311, b"s" * 2560),
            )
        with self.assertRaises(MLDSABackendFailure):
            validate_signature_output(MLDSAParameterSet.ML_DSA_44, b"s" * 2419)

    def test_malformed_verification_input_is_rejected_before_backend(self):
        with self.assertRaises(MLDSAInvalidInput) as caught:
            validate_verification_inputs(
                MLDSAParameterSet.ML_DSA_44,
                b"p" * 1312,
                b"message",
                b"",
                b"short",
            )
        self.assertEqual(caught.exception.code, MLDSAErrorCode.INVALID_INPUT_LENGTH)


class MLDSACapabilityTests(unittest.TestCase):
    def test_unsupported_signing_mode_is_structured(self):
        capabilities = MLDSACapabilities(
            frozenset({MLDSAParameterSet.ML_DSA_44}),
            frozenset({MLDSAOperation.SIGGEN}),
            frozenset({MLDSASigningMode.DETERMINISTIC}),
        )
        with self.assertRaises(MLDSAUnsupportedCapability) as caught:
            capabilities.require(
                MLDSAOperation.SIGGEN,
                MLDSAParameterSet.ML_DSA_44,
                MLDSASigningMode.HEDGED,
            )
        self.assertEqual(
            caught.exception.to_dict(),
            {
                "code": "unsupportedCapability",
                "message": "backend does not support the requested ML-DSA capability",
                "operation": "sigGen",
                "parameterSet": "ML-DSA-44",
            },
        )


if __name__ == "__main__":
    unittest.main()
