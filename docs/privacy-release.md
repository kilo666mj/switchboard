# Privacy gate for public releases

Agent Relay and Switchboard must pass this gate independently on the exact
source and Git refs intended for publication. Do not make the original private
repository histories public merely because their latest files pass a scan.

## Checks

```sh
python3 -m unittest discover -s scripts -p 'test_*.py'
python3 scripts/privacy-audit.py
# Gitleaks 8.30.0 was used for the initial audit.
gitleaks git . --log-opts=--all --redact=100 --ignore-gitleaks-allow
```

The privacy audit checks tracked files and non-ignored untracked files, all
commits reachable from local refs, historical file versions, commit messages,
author/committer identities, and annotated tags. It reports locations and
categories without matched values. Gitleaks separately checks credential
patterns. Inspect all findings, including binary files and symlinks. Never
paste credentials or personal values into issues, CI logs, or audit reports.

A work-in-progress source check is available with `--worktree-only`, but does
not clear a release. Secret scanning and heuristic patterns do not prove an
absence of all personal data: manually review documentation, examples, fixture
data, filenames, public account identifiers, and release artifacts too. Review
remote-only branches/tags before publishing; these local checks cover only
locally available refs. Hosting-service issues, releases, attachments, and
account profiles are outside the source audit and need their own review.

## Private history

The original histories contain identifying contributor metadata. Switchboard
also has historical internal hostnames. Current source cleanup does not remove
those historical values. Keep these original repositories private unless an
explicitly reviewed history migration removes the findings from every published
ref. No original history has been rewritten by the cleanup.

For a fresh public repository, prepare a separate source snapshot:

```sh
python3 scripts/public-snapshot.py . /tmp/project-public-review
cd /tmp/project-public-review
python3 scripts/privacy-audit.py
gitleaks git . --log-opts=--all --redact=100 --ignore-gitleaks-allow
```

The exporter refuses existing output directories, checks the source, copies
only tracked/non-ignored source files, runs secret scanning, and creates a new
local repository with a neutral placeholder identity. It does not copy original
history, remotes, ignored configuration, or credentials, and never pushes.
A snapshot is a review artifact, not authorization to publish. Select the
public contributor identity and confirm dependency attribution before release.
Both projects use MIT. The user approved their name and GitHub username for
publication; email addresses and private infrastructure remain excluded.
Preserve third-party licenses and legally required notices.

Build and test the snapshot from outside the private workspace. Recreate and
recheck it after every source change, then review the exact public-facing
content and refs. Original historical commit links will not exist in a fresh
public repository; coordinate that choice for both projects.
