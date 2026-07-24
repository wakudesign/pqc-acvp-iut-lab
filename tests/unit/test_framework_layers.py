import json
import tempfile
import unittest
from pathlib import Path

from pqc_acvp.acvp_schema import parse_mlkem_document
from pqc_acvp.framework import BackendMetadata, FrameworkError, FrameworkErrorCode
from pqc_acvp.mlkem import (
    BackendFailure,
    EncapsulationResult,
    ErrorCode,
    KeyCheckResult,
    KeyPair,
    MLKEMCapabilities,
    MLKEMOperation,
    MLKEMParameterSet,
    parameter_metadata,
)
from pqc_acvp.runner import run_file, run_text
from pqc_acvp.serialization import response_object, serialize_response


METADATA = BackendMetadata(
    "fake", "1", "abc", "test-target", "test-compiler", ("-O2",)
)
FIXTURES = Path(__file__).parents[1] / "fixtures" / "mlkem"


class FakeBackend:
    name = "fake"
    version = "1"
    capabilities = MLKEMCapabilities(frozenset(MLKEMParameterSet), frozenset(MLKEMOperation))

    def keygen_deterministic(self, parameter_set, entropy):
        sizes = parameter_metadata(parameter_set).sizes
        return KeyPair(b"e" * sizes.encapsulation_key, b"d" * sizes.decapsulation_key)

    def encaps_deterministic(self, parameter_set, encapsulation_key, entropy):
        sizes = parameter_metadata(parameter_set).sizes
        return EncapsulationResult(b"c" * sizes.ciphertext, b"k" * 32)

    def decaps(self, parameter_set, decapsulation_key, ciphertext):
        return b"k" * 32

    def check_encapsulation_key(self, parameter_set, encapsulation_key):
        return KeyCheckResult(True)

    def check_decapsulation_key(self, parameter_set, decapsulation_key):
        return KeyCheckResult(True)


def keygen_document():
    return [
        {"acvVersion": "1.0"},
        {
            "vsId": 1,
            "algorithm": "ML-KEM",
            "mode": "keyGen",
            "revision": "FIPS203",
            "testGroups": [{
                "tgId": 1,
                "parameterSet": "ML-KEM-512",
                "testType": "AFT",
                "tests": [{"tcId": 1, "d": "00" * 32, "z": "11" * 32}],
            }],
        },
    ]


class SchemaLayerTests(unittest.TestCase):
    def test_parser_returns_typed_model_without_backend(self):
        parsed = parse_mlkem_document(json.dumps(keygen_document()))
        self.assertEqual(parsed.mode, "keyGen")
        self.assertIs(parsed.groups[0].parameter_set, MLKEMParameterSet.ML_KEM_512)
        self.assertEqual(parsed.groups[0].tests[0].tc_id, 1)

    def test_parser_rejects_unknown_function(self):
        document = keygen_document()
        document[1]["mode"] = "encapDecap"
        document[1]["testGroups"][0]["function"] = "unknown"
        with self.assertRaises(FrameworkError):
            parse_mlkem_document(json.dumps(document))

    def test_parser_rejects_missing_vector_set_field(self):
        document = keygen_document()
        del document[1]["algorithm"]
        with self.assertRaises(FrameworkError) as caught:
            parse_mlkem_document(json.dumps(document))
        self.assertEqual(caught.exception.error.code, FrameworkErrorCode.MISSING_FIELD.value)

    def test_parser_rejects_missing_version_field(self):
        document = keygen_document()
        document[0] = {}
        with self.assertRaises(FrameworkError) as caught:
            parse_mlkem_document(json.dumps(document))
        self.assertEqual(caught.exception.error.code, FrameworkErrorCode.MISSING_FIELD.value)

    def test_parser_rejects_unknown_fields_at_each_schema_level(self):
        mutations = (
            lambda document: document[1].update({"algoritm": "ML-KEM"}),
            lambda document: document[1]["testGroups"][0].update({"functon": "keyGen"}),
            lambda document: document[1]["testGroups"][0]["tests"][0].update({"seed": "00"}),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                document = keygen_document()
                mutate(document)
                with self.assertRaises(FrameworkError) as caught:
                    parse_mlkem_document(json.dumps(document))
                self.assertEqual(caught.exception.error.code, FrameworkErrorCode.UNKNOWN_FIELD.value)

    def test_parser_rejects_unsupported_mode(self):
        document = keygen_document()
        document[1]["mode"] = "keyGeneration"
        with self.assertRaises(FrameworkError) as caught:
            parse_mlkem_document(json.dumps(document))
        self.assertEqual(caught.exception.error.code, FrameworkErrorCode.UNSUPPORTED_MODE.value)

    def test_parser_rejects_unsupported_function_with_stable_code(self):
        document = keygen_document()
        document[1]["mode"] = "encapDecap"
        document[1]["testGroups"][0]["function"] = "deriveSecret"
        with self.assertRaises(FrameworkError) as caught:
            parse_mlkem_document(json.dumps(document))
        self.assertEqual(caught.exception.error.code, FrameworkErrorCode.UNSUPPORTED_FUNCTION.value)


class InputValidationTests(unittest.TestCase):
    def _run_keygen_with(self, field, value):
        document = keygen_document()
        document[1]["testGroups"][0]["tests"][0][field] = value
        return run_text(json.dumps(document), FakeBackend(), METADATA)

    def test_hex_decoding_accepts_mixed_case(self):
        result = self._run_keygen_with("d", "aA" * 32)
        self.assertEqual(result.summary.status, "generated")
        self.assertIsNotNone(result.serialized_response)

    def test_hex_decoding_rejects_odd_length(self):
        result = self._run_keygen_with("d", "0" * 63)
        self.assertEqual(result.summary.errors[0].code, FrameworkErrorCode.INVALID_HEX.value)
        self.assertIsNone(result.serialized_response)

    def test_hex_decoding_rejects_invalid_character(self):
        result = self._run_keygen_with("z", "GG" * 32)
        self.assertEqual(result.summary.errors[0].code, FrameworkErrorCode.INVALID_HEX.value)
        self.assertIsNone(result.serialized_response)

    def test_hex_decoding_rejects_size_mismatch_before_backend(self):
        class MustNotRunBackend(FakeBackend):
            def keygen_deterministic(self, parameter_set, entropy):
                self.fail_if_called = True
                raise AssertionError("backend must not receive size-mismatched input")

        document = keygen_document()
        document[1]["testGroups"][0]["tests"][0]["d"] = "00" * 31
        backend = MustNotRunBackend()
        result = run_text(json.dumps(document), backend, METADATA)
        self.assertFalse(hasattr(backend, "fail_if_called"))
        self.assertEqual(result.summary.errors[0].code, FrameworkErrorCode.INVALID_FIELD.value)
        self.assertIsNone(result.serialized_response)

    def test_missing_test_input_does_not_produce_response(self):
        document = keygen_document()
        del document[1]["testGroups"][0]["tests"][0]["z"]
        result = run_text(json.dumps(document), FakeBackend(), METADATA)
        self.assertEqual(result.summary.errors[0].code, FrameworkErrorCode.MISSING_FIELD.value)
        self.assertIsNone(result.serialized_response)


class SerializationLayerTests(unittest.TestCase):
    def test_response_construction_and_serialization_are_separate(self):
        parsed = parse_mlkem_document(json.dumps(keygen_document()))
        response = response_object(parsed, ({"tgId": 1, "tests": [{"tcId": 1, "ek": "AA", "dk": "BB"}]},))
        serialized = serialize_response(response)
        self.assertTrue(serialized.endswith("\n"))
        self.assertEqual(json.loads(serialized)[1]["testGroups"][0]["tests"][0]["ek"], "AA")

    def test_golden_fixture_response_matches_semantically(self):
        request = (FIXTURES / "key-check-request.json").read_text(encoding="utf-8")
        expected = json.loads((FIXTURES / "key-check-response.json").read_text(encoding="utf-8"))
        result = run_text(request, FakeBackend(), METADATA)
        self.assertIsNotNone(result.serialized_response)
        self.assertEqual(json.loads(result.serialized_response), expected)


class RunnerLayerTests(unittest.TestCase):
    def test_runner_produces_response_and_summary(self):
        result = run_text(json.dumps(keygen_document()), FakeBackend(), METADATA)
        self.assertIsNotNone(result.serialized_response)
        self.assertEqual(result.summary.tests_seen, 1)
        self.assertEqual(result.summary.tests_produced, 1)
        self.assertEqual(result.summary.function_counts, {"keyGen": 1})

    def test_backend_failure_produces_no_partial_response_or_file(self):
        class FailingBackend(FakeBackend):
            def keygen_deterministic(self, parameter_set, entropy):
                raise BackendFailure(ErrorCode.BACKEND_FAILURE, "fixed backend failure")

        result = run_text(json.dumps(keygen_document()), FailingBackend(), METADATA)
        self.assertIsNone(result.serialized_response)
        self.assertEqual(result.summary.status, "failed")
        self.assertEqual(result.summary.tests_produced, 0)
        self.assertEqual(result.summary.errors[0].code, "backendError")

        with tempfile.TemporaryDirectory() as temporary:
            request = Path(temporary) / "request.json"
            response = Path(temporary) / "response.json"
            request.write_text(json.dumps(keygen_document()), encoding="utf-8")
            summary = run_file(request, response, FailingBackend(), METADATA)
            self.assertEqual(summary.status, "failed")
            self.assertFalse(response.exists())

    def test_backend_metadata_is_structured(self):
        self.assertEqual(METADATA.to_dict()["flags"], ["-O2"])


if __name__ == "__main__":
    unittest.main()
