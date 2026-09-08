import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("privacy_audit", Path(__file__).with_name("privacy-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


class PrivacyAuditTest(unittest.TestCase):
    def test_redaction_and_documentation_examples(self):
        findings = []
        # Assemble synthetic sensitive-looking fixtures to avoid source-scan noise.
        value = ("/home/" + "private-user/file " + "user@" + "organization.tld " + ".".join(["service", "private", "internal"]) + " " + ".".join(["10", "2", "3", "4"])).encode()
        audit.inspect(value, {"file": "fixture"}, findings)
        self.assertEqual({f["category"] for f in findings}, {"personal-home-path", "email-address", "internal-hostname", "ipv4-address"})
        output = json.dumps(findings)
        self.assertNotIn("private-user", output)
        self.assertNotIn("organization.tld", output)
        examples = b"developer@example.com https://relay.example.internal 192.0.2.10 127.0.0.1 /home/developer/file Path.home()"
        findings = []
        audit.inspect(examples, {"file": "fixture"}, findings)
        self.assertEqual(findings, [])

    def test_deleted_history_and_author_metadata_are_checked(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            def git(*args):
                return subprocess.check_output(["git", "-C", tmp, *args], stderr=subprocess.DEVNULL)
            git("init", "-q")
            git("config", "user.name", "Synthetic Person")
            git("config", "user.email", "synthetic@" + "organization.tld")
            private = repo / "removed.txt"
            private.write_text("https://" + ".".join(["private", "private", "internal"]) + "\n")
            git("add", ".")
            git("commit", "-qm", "Initial fixture")
            private.unlink()
            git("add", "-u")
            git("commit", "-qm", "Remove fixture")
            report = audit.audit(repo)
            self.assertEqual(report["commits_checked"], 2)
            self.assertTrue(any(f["category"] == "internal-hostname" and f["scope"] == "history" for f in report["findings"]))
            self.assertEqual(sum(f["category"] == "git-identity-metadata" for f in report["findings"]), 4)
            self.assertEqual(audit.audit(repo, history=False)["findings"], [])


if __name__ == "__main__":
    unittest.main()
