#!/usr/bin/env python3
"""Redacted pre-release checks for local files and reachable Git history.

Heuristics complement secret scanning and manual review; they are not proof that
all personal information has been found. No matched values are printed.
"""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

PATTERNS = {
    "personal-home-path": re.compile(r"(?:/home/|/Users/|/mnt/linux_home/|[A-Za-z]:\\Users\\)(?!developer\b|user\b|example\b|runner\b|test\b)[A-Za-z0-9][A-Za-z0-9._-]*"),
    "email-address": re.compile(r"(?<![\w.+-])[\w.+-]+@(?:[\w-]+\.)+[A-Za-z]{2,}"),
    "internal-hostname": re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+(?:internal|lan|local|home|corp)\b(?!\s*\()"),
    "ipv4-address": re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"),
    "private-key": re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----"),
}
EXAMPLE_DOMAINS = ("example.com", "example.net", "example.org", "example.internal", "example.test", "example.invalid")
DOCUMENTATION_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
ALLOWED_EMAILS = {
    "49699333+dependabot[bot]@users.noreply.github.com",
    "noreply@github.com",
    "support@github.com",
}
ALLOWED_GIT_IDENTITIES = {
    b"Project Contributors <release@example.invalid>",
    b"dependabot[bot] <49699333+dependabot[bot]@users.noreply.github.com>",
    b"GitHub <noreply@github.com>",
}


def git(repo, *args):
    return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.DEVNULL)


def allowed(category, value):
    if category == "email-address":
        if value.lower() in ALLOWED_EMAILS:
            return True
        domain = value.rsplit("@", 1)[1].lower()
        return domain.endswith((".test", ".invalid", ".example")) or any(domain == d or domain.endswith("." + d) for d in EXAMPLE_DOMAINS)
    if category == "internal-hostname":
        return value.endswith((".example.internal", ".example.local", ".example.lan")) or value in ("example.internal", "example.local", "example.lan")
    if category == "ipv4-address":
        try:
            ip = ipaddress.ip_address(value)
        except ValueError:
            return True  # Usually a version string.
        return ip.is_loopback or ip.is_unspecified or any(ip in network for network in DOCUMENTATION_NETS)
    return False


def inspect(data, location, findings):
    if b"\0" in data:
        findings.append({**location, "category": "binary-needs-review"})
        return
    for number, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
        for category, pattern in PATTERNS.items():
            if any(not allowed(category, match.group()) for match in pattern.finditer(line)):
                findings.append({**location, "line": number, "category": category})


def audit(repo, history=True):
    repo = Path(repo).resolve()
    findings = []
    files = set(git(repo, "ls-files", "-z", "--cached", "--others", "--exclude-standard").decode().split("\0")) - {""}
    for name in sorted(files):
        path = repo / name
        if path.is_symlink():
            findings.append({"scope": "worktree", "file": name, "category": "symlink-needs-review"})
        elif path.is_file():
            inspect(path.read_bytes(), {"scope": "worktree", "file": name}, findings)
    commits = git(repo, "rev-list", "--all").decode().splitlines() if history else []
    seen = set()
    for commit in commits:
        raw = git(repo, "cat-file", "commit", commit)
        header, _, message = raw.partition(b"\n\n")
        for line in header.splitlines():
            if line.startswith((b"author ", b"committer ")):
                # Even valid Git author names/emails are identifying information.
                identity = line.split(b" ", 1)[1].rsplit(b">", 1)[0] + b">"
                if identity not in ALLOWED_GIT_IDENTITIES:
                    findings.append({"scope": "history", "commit": commit[:12], "category": "git-identity-metadata", "field": line.split(b" ", 1)[0].decode()})
        inspect(message, {"scope": "history", "commit": commit[:12], "file": "(commit message)"}, findings)
        for entry in git(repo, "ls-tree", "-rz", "--full-tree", commit).split(b"\0"):
            if not entry:
                continue
            metadata, name = entry.split(b"\t", 1)
            mode, kind, oid = metadata.split()
            if kind != b"blob":
                findings.append({"scope": "history", "commit": commit[:12], "file": name.decode(), "category": "submodule-needs-review"})
                continue
            key = (oid, name)
            if key in seen:
                continue
            seen.add(key)
            inspect(git(repo, "cat-file", "blob", oid.decode()), {"scope": "history", "commit": commit[:12], "file": name.decode()}, findings)
    # Annotated tags carry their own messages and tagger identities.
    tags = git(repo, "for-each-ref", "refs/tags", "--format=%(objecttype) %(objectname)").decode().splitlines() if history else []
    for tag in tags:
        kind, oid = tag.split()
        if kind == "tag":
            data = git(repo, "cat-file", "tag", oid)
            inspect(data, {"scope": "history", "object": oid[:12], "file": "(annotated tag)"}, findings)
            if b"\ntagger " in data:
                findings.append({"scope": "history", "object": oid[:12], "category": "git-identity-metadata", "field": "tagger"})
    return {"files_checked": len(files), "commits_checked": len(commits), "historical_file_versions_checked": len(seen), "findings": findings}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("repository", nargs="?", default=".")
    parser.add_argument("--worktree-only", action="store_true")
    args = parser.parse_args()
    try:
        report = audit(args.repository, not args.worktree_only)
    except (OSError, subprocess.CalledProcessError) as error:
        print(json.dumps({"error": "audit could not complete", "type": type(error).__name__}))
        return 2
    print(json.dumps(report, indent=2))
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    sys.exit(main())
