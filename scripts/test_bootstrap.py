import importlib.util
import json
from pathlib import Path
import tomllib
import unittest

spec = importlib.util.spec_from_file_location("bootstrap", Path(__file__).with_name("switchboard-connect.py"))
bootstrap = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bootstrap)

class BootstrapTest(unittest.TestCase):
    def test_preserves_existing_settings_and_is_idempotent(self):
        old = '''model = "configured-model"
[mcp_servers.switchboard]
url = "https://old.invalid/mcp"
bearer_token_env_var = "OLD_ENV"
default_tools_approval_mode = "prompt"
[mcp_servers.switchboard.tools.remember]
approval_mode = "prompt"
[mcp_servers.other]
command = "other"
'''
        new = bootstrap.configure(old, "https://switchboard.example.internal/mcp/sessions", "NEW_ENV")
        parsed = tomllib.loads(new)
        self.assertEqual(parsed["model"], "configured-model")
        self.assertEqual(parsed["mcp_servers"]["switchboard"]["default_tools_approval_mode"], "prompt")
        self.assertEqual(parsed["mcp_servers"]["other"], {"command": "other"})
        self.assertEqual(bootstrap.configure(new, "https://switchboard.example.internal/mcp/sessions", "NEW_ENV"), new)

    def test_new_config_defaults_to_write_approvals(self):
        new = bootstrap.configure("", "https://switchboard.example.internal/mcp/sessions", "TOKEN")
        self.assertEqual(tomllib.loads(new)["mcp_servers"]["switchboard"]["default_tools_approval_mode"], "writes")

    def test_json_clients_preserve_unrelated_configuration(self):
        for client in ["claude", "qwen", "opencode"]:
            old = json.dumps({"model": "keep", "security": {"approval": "ask"}})
            new = bootstrap.configure_json(old, "https://host/mcp/sessions", "CLIENT_TOKEN", client)
            parsed = json.loads(new)
            self.assertEqual(parsed["security"], {"approval": "ask"})
            self.assertEqual(parsed["model"], "keep")
            self.assertIn("CLIENT_TOKEN", new)
            self.assertEqual(bootstrap.configure_json(new, "https://host/mcp/sessions", "CLIENT_TOKEN", client), new)

    def test_rejects_credentials_and_non_https(self):
        for url in ["http://host/mcp", "https://secret@host/mcp", "https://host/mcp?token=secret"]:
            with self.assertRaises(ValueError):
                bootstrap.configure("", url, "TOKEN")

if __name__ == "__main__":
    unittest.main()
