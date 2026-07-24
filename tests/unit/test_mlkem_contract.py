import unittest

from pqc_acvp.mlkem import (
    BackendFailure,
    EncapsulationEntropy,
    EncapsulationResult,
    ErrorCode,
    InvalidInput,
    KeyCheckFailure,
    KeyCheckResult,
    KeyGenEntropy,
    KeyPair,
    MLKEMCapabilities,
    MLKEMOperation,
    MLKEMParameterSet,
    UnsupportedCapability,
    parameter_metadata,
    validate_decapsulation_inputs,
    validate_encapsulation_output,
    validate_key_pair_output,
    validate_shared_secret_output,
)


class ParameterSetTests(unittest.TestCase):
    def test_all_parameter_metadata(self):
        expected = {
            MLKEMParameterSet.ML_KEM_512: (800, 1632, 768, 32),
            MLKEMParameterSet.ML_KEM_768: (1184, 2400, 1088, 32),
            MLKEMParameterSet.ML_KEM_1024: (1568, 3168, 1568, 32),
        }
        for parameter_set, sizes in expected.items():
            actual = parameter_metadata(parameter_set).sizes
            self.assertEqual(
                (actual.encapsulation_key, actual.decapsulation_key, actual.ciphertext, actual.shared_secret),
                sizes,
            )

    def test_exact_acvp_names_parse(self):
        expected = {
            "ML-KEM-512": MLKEMParameterSet.ML_KEM_512,
            "ML-KEM-768": MLKEMParameterSet.ML_KEM_768,
            "ML-KEM-1024": MLKEMParameterSet.ML_KEM_1024,
        }
        for name, parameter_set in expected.items():
            self.assertIs(MLKEMParameterSet.parse(name), parameter_set)

    def test_unknown_parameter_set_is_invalid_input(self):
        with self.assertRaises(InvalidInput) as caught:
            MLKEMParameterSet.parse("Kyber768")
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_PARAMETER_SET)


class EntropyBoundaryTests(unittest.TestCase):
    def test_keygen_entropy_requires_two_32_byte_values(self):
        entropy = KeyGenEntropy.checked(b"d" * 32, b"z" * 32)
        self.assertEqual(len(entropy.d), 32)
        self.assertEqual(len(entropy.z), 32)

    def test_encapsulation_entropy_is_acvp_m(self):
        self.assertEqual(EncapsulationEntropy.checked(b"m" * 32).m, b"m" * 32)

    def test_mutable_entropy_is_rejected(self):
        with self.assertRaises(InvalidInput) as caught:
            KeyGenEntropy.checked(bytearray(32), b"z" * 32)  # type: ignore[arg-type]
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_INPUT_TYPE)

    def test_wrong_entropy_length_is_rejected(self):
        with self.assertRaises(InvalidInput) as caught:
            EncapsulationEntropy.checked(b"m" * 31)
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_INPUT_LENGTH)

    def test_direct_constructor_cannot_bypass_validation(self):
        with self.assertRaises(InvalidInput):
            KeyGenEntropy(b"d" * 31, b"z" * 32)
        with self.assertRaises(InvalidInput):
            EncapsulationEntropy(b"m" * 33)


class CapabilityTests(unittest.TestCase):
    def test_supported_capability_returns_parsed_parameter_set(self):
        capabilities = MLKEMCapabilities(
            frozenset({MLKEMParameterSet.ML_KEM_512}),
            frozenset({MLKEMOperation.DECAPS}),
        )
        self.assertIs(
            capabilities.require(MLKEMOperation.DECAPS, "ML-KEM-512"),
            MLKEMParameterSet.ML_KEM_512,
        )

    def test_unsupported_capability_is_structured(self):
        capabilities = MLKEMCapabilities(
            frozenset({MLKEMParameterSet.ML_KEM_512}),
            frozenset({MLKEMOperation.DECAPS}),
        )
        with self.assertRaises(UnsupportedCapability) as caught:
            capabilities.require(MLKEMOperation.ENCAPS_DETERMINISTIC, "ML-KEM-512")
        self.assertEqual(
            caught.exception.to_dict(),
            {
                "code": "unsupportedCapability",
                "message": "backend does not support the requested ML-KEM capability",
                "operation": "encapsDeterministic",
                "parameterSet": "ML-KEM-512",
            },
        )


class OutputValidationTests(unittest.TestCase):
    def test_valid_outputs(self):
        metadata = parameter_metadata("ML-KEM-512")
        sizes = metadata.sizes
        key_pair = KeyPair(b"e" * sizes.encapsulation_key, b"d" * sizes.decapsulation_key)
        encapsulation = EncapsulationResult(b"c" * sizes.ciphertext, b"k" * 32)
        self.assertIs(validate_key_pair_output(metadata.parameter_set, key_pair), key_pair)
        self.assertIs(validate_encapsulation_output(metadata.parameter_set, encapsulation), encapsulation)
        self.assertEqual(validate_shared_secret_output(b"k" * 32), b"k" * 32)

    def test_backend_wrong_output_length_is_backend_failure(self):
        with self.assertRaises(BackendFailure) as caught:
            validate_shared_secret_output(b"k" * 31)
        self.assertEqual(caught.exception.code, ErrorCode.BACKEND_FAILURE)

    def test_decapsulation_rejects_wrong_length_before_backend(self):
        sizes = parameter_metadata("ML-KEM-768").sizes
        with self.assertRaises(InvalidInput) as caught:
            validate_decapsulation_inputs(
                "ML-KEM-768",
                b"d" * sizes.decapsulation_key,
                b"c" * (sizes.ciphertext - 1),
            )
        self.assertEqual(caught.exception.code, ErrorCode.INVALID_INPUT_LENGTH)

    def test_same_length_modified_ciphertext_is_well_formed_input(self):
        sizes = parameter_metadata("ML-KEM-768").sizes
        modified = bytearray(b"c" * sizes.ciphertext)
        modified[0] ^= 1
        parsed = validate_decapsulation_inputs(
            "ML-KEM-768",
            b"d" * sizes.decapsulation_key,
            bytes(modified),
        )
        self.assertIs(parsed, MLKEMParameterSet.ML_KEM_768)


class KeyCheckResultTests(unittest.TestCase):
    def test_valid_result_has_no_failure_reason(self):
        self.assertEqual(KeyCheckResult(valid=True), KeyCheckResult(True, None))

    def test_invalid_result_requires_reason(self):
        result = KeyCheckResult(False, KeyCheckFailure.HASH_MISMATCH)
        self.assertFalse(result.valid)
        with self.assertRaises(ValueError):
            KeyCheckResult(False)

    def test_valid_result_cannot_have_failure_reason(self):
        with self.assertRaises(ValueError):
            KeyCheckResult(True, KeyCheckFailure.NON_CANONICAL_ENCODING)


if __name__ == "__main__":
    unittest.main()
