import json
import unittest

from pqc_acvp.framework import BackendMetadata, FrameworkError
from pqc_acvp.mldsa import (
    MLDSACapabilities,
    MLDSAKeyPair,
    MLDSAOperation,
    MLDSAParameterSet,
    MLDSASigningMode,
    MLDSAVerificationResult,
    mldsa_parameter_metadata,
)
from pqc_acvp.mldsa_runner import run_mldsa_text
from pqc_acvp.mldsa_schema import parse_mldsa_document


META = BackendMetadata("fake", "1", "0" * 40, "test", "test")


class FakeBackend:
    name = "fake"
    version = "1"
    capabilities = MLDSACapabilities(
        frozenset(MLDSAParameterSet),
        frozenset(MLDSAOperation),
        frozenset(MLDSASigningMode),
    )

    def __init__(self):
        self.calls = 0

    def keygen_deterministic(self, parameter_set, seed):
        self.calls += 1
        sizes = mldsa_parameter_metadata(parameter_set).sizes
        return MLDSAKeyPair(b"p" * sizes.public_key, b"s" * sizes.secret_key)

    def sign_pure(self, parameter_set, secret_key, message, context, randomness):
        self.calls += 1
        return b"g" * mldsa_parameter_metadata(parameter_set).sizes.signature

    def verify_pure(self, parameter_set, public_key, message, context, signature):
        self.calls += 1
        return MLDSAVerificationResult(signature[0] == 0x67)


def vector(mode, group):
    return json.dumps({
        "vsId": 7,
        "algorithm": "ML-DSA",
        "mode": mode,
        "revision": "FIPS204",
        "testGroups": [group],
    })


class MLDSAFrameworkTests(unittest.TestCase):
    def test_three_modes_have_expected_response_schema_and_counts(self):
        cases = (
            ("keyGen", {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "tests": [{"tcId": 1, "seed": "00" * 32}]}, {"pk", "sk"}),
            ("sigGen", {"tgId": 2, "testType": "AFT", "parameterSet": "ML-DSA-44", "deterministic": True, "signatureInterface": "external", "preHash": "pure", "tests": [{"tcId": 2, "message": "01", "sk": "02" * 2560, "context": ""}]}, {"signature"}),
            ("sigVer", {"tgId": 3, "testType": "AFT", "parameterSet": "ML-DSA-44", "signatureInterface": "external", "preHash": "pure", "tests": [{"tcId": 3, "message": "01", "pk": "02" * 1312, "context": "", "signature": "67" * 2420}]}, {"testPassed"}),
        )
        for mode, group, fields in cases:
            with self.subTest(mode=mode):
                result = run_mldsa_text(vector(mode, group), FakeBackend(), META)
                self.assertEqual(result.summary.status, "generated")
                self.assertEqual(result.summary.tests_seen, 1)
                self.assertEqual(result.summary.tests_produced, 1)
                self.assertEqual(result.summary.function_counts, {mode: 1})
                response = json.loads(result.serialized_response)
                test = response["testGroups"][0]["tests"][0]
                self.assertEqual(set(test) - {"tcId"}, fields)

    def test_hedged_signing_requires_exact_rnd(self):
        group = {"tgId": 2, "testType": "AFT", "parameterSet": "ML-DSA-44", "deterministic": False, "signatureInterface": "external", "preHash": "pure", "tests": [{"tcId": 9, "message": "01", "sk": "02" * 2560, "context": "", "rnd": "03" * 31}]}
        backend = FakeBackend()
        result = run_mldsa_text(vector("sigGen", group), backend, META)
        self.assertIsNone(result.serialized_response)
        self.assertEqual(result.summary.status, "failed")
        self.assertEqual(result.summary.tests_produced, 0)
        self.assertEqual(result.summary.errors[0].to_dict()["tcId"], 9)
        self.assertEqual(backend.calls, 0)

    def test_malformed_key_signature_and_context_fail_before_backend(self):
        malformed = (
            ("sigGen", {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "deterministic": True, "signatureInterface": "external", "preHash": "pure", "tests": [{"tcId": 1, "message": "01", "sk": "00", "context": ""}]}),
            ("sigVer", {"tgId": 2, "testType": "AFT", "parameterSet": "ML-DSA-44", "signatureInterface": "external", "preHash": "pure", "tests": [{"tcId": 2, "message": "01", "pk": "00" * 1312, "context": "", "signature": "00"}]}),
            ("sigVer", {"tgId": 3, "testType": "AFT", "parameterSet": "ML-DSA-44", "signatureInterface": "external", "preHash": "pure", "tests": [{"tcId": 3, "message": "01", "pk": "00" * 1312, "context": "00" * 256, "signature": "00" * 2420}]}),
        )
        for mode, group in malformed:
            backend = FakeBackend()
            result = run_mldsa_text(vector(mode, group), backend, META)
            self.assertEqual(result.summary.status, "failed")
            self.assertIsNone(result.serialized_response)
            self.assertEqual(backend.calls, 0)

    def test_unsupported_mode_prehash_and_internal_are_parse_errors(self):
        base = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "signatureInterface": "external", "preHash": "pure", "tests": []}
        unsupported = (
            vector("keyGen", {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "tests": []}).replace('"keyGen"', '"signature"', 1),
            vector("sigVer", {**base, "preHash": "preHash"}),
            vector("sigVer", {**base, "signatureInterface": "internal"}),
        )
        for document in unsupported:
            with self.assertRaises(FrameworkError) as caught:
                parse_mldsa_document(document)
            self.assertIn(caught.exception.error.code, {"unsupportedMode", "unsupportedFunction"})

    def test_unknown_fields_are_rejected(self):
        group = {"tgId": 1, "testType": "AFT", "parameterSet": "ML-DSA-44", "tests": [], "surprise": True}
        with self.assertRaises(FrameworkError) as caught:
            parse_mldsa_document(vector("keyGen", group))
        self.assertEqual(caught.exception.error.code, "unknownField")


if __name__ == "__main__":
    unittest.main()
