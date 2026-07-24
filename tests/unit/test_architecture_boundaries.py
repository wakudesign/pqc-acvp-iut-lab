import ast
import unittest
from pathlib import Path


BACKENDS = Path(__file__).parents[2] / "src" / "pqc_acvp" / "backends"
FORBIDDEN_NETWORK_IMPORTS = {
    "aiohttp",
    "http.client",
    "httpx",
    "requests",
    "socket",
    "urllib",
    "urllib3",
}
FORBIDDEN_LIFECYCLE_SYMBOLS = {
    "acvts",
    "auth_token",
    "authorization",
    "download_vectors",
    "jwt",
    "login",
    "poll_verdict",
    "register_session",
    "test_session",
    "upload_response",
}


def backend_trees():
    for path in sorted(BACKENDS.glob("*.py")):
        yield path, ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


class BackendBoundaryTests(unittest.TestCase):
    def test_backends_do_not_import_network_clients(self):
        violations = []
        for path, tree in backend_trees():
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    names = [node.module]
                for name in names:
                    if any(name == banned or name.startswith(f"{banned}.") for banned in FORBIDDEN_NETWORK_IMPORTS):
                        violations.append(f"{path.name}:{node.lineno}:{name}")
        self.assertEqual(violations, [])

    def test_backends_do_not_reference_acvts_session_lifecycle(self):
        violations = []
        for path, tree in backend_trees():
            for node in ast.walk(tree):
                value = None
                if isinstance(node, ast.Name):
                    value = node.id
                elif isinstance(node, ast.Attribute):
                    value = node.attr
                if value and value.lower() in FORBIDDEN_LIFECYCLE_SYMBOLS:
                    violations.append(f"{path.name}:{node.lineno}:{value}")
        self.assertEqual(violations, [])


if __name__ == "__main__":
    unittest.main()

