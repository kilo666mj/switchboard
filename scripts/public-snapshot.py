#!/usr/bin/env python3
"""Prepare a separately audited source snapshot without altering original history.

This never pushes, sets a remote, or changes the original repository. Review
licensing, attribution, release readiness, and public identity before publishing.
"""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

spec = importlib.util.spec_from_file_location("privacy_audit", Path(__file__).with_name("privacy-audit.py"))
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def run():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", type=Path)
    parser.add_argument("output", type=Path, help="New directory outside the source repository")
    args = parser.parse_args()
    source, output = args.repository.resolve(), args.output.resolve()
    if output.exists() or output.is_relative_to(source):
        parser.error("output must be a new directory outside the source repository")
    if not shutil.which("gitleaks"):
        parser.error("gitleaks must be installed before preparing a public snapshot")
    report = audit.audit(source, history=False)
    if report["findings"]:
        print(json.dumps(report, indent=2))
        return 1
    files = set(audit.git(source, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")) - {""}
    output.mkdir(parents=True, mode=0o700)
    for name in sorted(files):
        path = source / name
        if path.is_file() and not path.is_symlink():
            target = output / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(path, target)
    # Capture tool output: even redacted secret reports can include source lines.
    leak = subprocess.run(["gitleaks", "dir", str(output), "--redact=100", "--no-banner", "--log-level", "error", "--ignore-gitleaks-allow"], capture_output=True)
    if leak.returncode:
        print(json.dumps({"error": "snapshot secret scan did not pass", "exit_code": leak.returncode}))
        return 1
    git_env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    git_env.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1",
                    "GIT_AUTHOR_NAME": "Project Contributors", "GIT_COMMITTER_NAME": "Project Contributors",
                    "GIT_AUTHOR_EMAIL": "release@example.invalid", "GIT_COMMITTER_EMAIL": "release@example.invalid"})
    def git(*parts):
        subprocess.run(["git", "-c", "core.hooksPath=" + os.devnull, "-C", str(output), *parts], check=True, capture_output=True, env=git_env)
    git("init", "-q", "-b", "main")
    git("config", "user.name", "Project Contributors")
    git("config", "user.email", "release@example.invalid")
    git("config", "commit.gpgsign", "false")
    git("add", ".")
    git("commit", "-qm", "Prepare public source snapshot")
    final = audit.audit(output)
    if final["findings"]:
        print(json.dumps(final, indent=2))
        return 1
    print(json.dumps({"snapshot": str(output), "files_checked": final["files_checked"], "commits_checked": final["commits_checked"], "findings": [], "published": False}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(run())
