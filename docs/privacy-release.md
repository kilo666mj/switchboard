# Privacy gate for public releases

Run this gate against the exact Switchboard commit and Git refs intended for a
public release.

## Required checks

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/privacy-audit.py
# Gitleaks 8.30.0 was used for the initial audit.
gitleaks git . --log-opts=--all --redact=100 --ignore-gitleaks-allow
```

The privacy audit checks tracked files, non-ignored untracked files, every
commit reachable from local refs, historical file versions, commit messages,
author and committer identities, and annotated tags. Gitleaks separately checks
credential patterns. Inspect every finding, including binary files and
symlinks. Never paste credentials or personal values into issues, CI logs, or
audit reports.

A work-in-progress source check is available with `--worktree-only`, but it does
not clear a release. Secret scanning and heuristic patterns cannot prove the
absence of all personal data. Manually review documentation, examples, fixture
data, filenames, public account identifiers, and the final release artifacts.
Review remote-only branches and tags separately because local checks cover only
locally available refs. Hosting-service issues, releases, attachments, and
account profiles are also outside the source audit.

## Release procedure

1. Start from a clean checkout of the public repository and fetch every public
   branch and tag.
2. Run the tests, full privacy audit, and Gitleaks command above.
3. Build and smoke-test the release archives as described in
   [releases.md](releases.md).
4. Confirm dependency attribution and preserve third-party licenses and legally
   required notices.
5. Create the release tag from the exact commit that passed hosted CI,
   dependency security, and CodeQL.
6. Upload only the verified archives and checksum file, then verify the hosted
   release metadata and downloaded checksums.

Repeat the gate after every source change. A passing automated scan is evidence
for review, not authorization to publish.
