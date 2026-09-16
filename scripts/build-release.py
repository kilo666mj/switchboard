#!/usr/bin/env python3
"""Build private, reproducible review archives. Never uploads or publishes."""
import argparse
import gzip
import hashlib
import io
import os
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile
from release_notices import collect

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--output', type=Path, required=True, help='new directory')
    parser.add_argument('--target', action='append', choices=['linux/amd64', 'linux/arm64'])
    parser.add_argument('--go-notices', type=Path, help='installed Go LICENSE/PATENTS directory when packaged outside GOROOT')
    args = parser.parse_args()
    if not re.fullmatch(r'v?[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9]+(?:[.-][A-Za-z0-9]+)*)?', args.version):
        parser.error('version must be a semantic version, optionally with a prerelease suffix')
    output = args.output.resolve()
    if output.exists():
        parser.error('output directory already exists; refusing to overwrite')
    output.mkdir(parents=True, mode=0o700)
    targets = sorted(set(args.target or ['linux/amd64', 'linux/arm64']))
    hashes = []
    with tempfile.TemporaryDirectory(prefix='switchboard-release-') as temporary:
        for target in targets:
            system, arch = target.split('/')
            binary = Path(temporary) / 'switchboard'
            log_watcher_module = Path(temporary) / 'switchboard-module-log-watcher'
            env = dict(os.environ, GOOS=system, GOARCH=arch, CGO_ENABLED='0', GOWORK='off', GOFLAGS='')
            subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
                            '-ldflags=-s -w -X main.version=' + args.version,
                            '-o', str(binary), './cmd/switchboard'], cwd=ROOT, env=env, check=True)
            subprocess.run(['go', 'build', '-mod=readonly', '-trimpath', '-buildvcs=false',
                            '-ldflags=-s -w -X main.version=' + args.version,
                            '-o', str(log_watcher_module), './modules/log_watcher'], cwd=ROOT, env=env, check=True)
            notices, dependencies = collect(ROOT, env,
                                            package=['./cmd/switchboard', './modules/log_watcher'],
                                            go_notices=args.go_notices)
            notice_path, dependency_path = Path(temporary) / 'THIRD_PARTY_NOTICES.txt', Path(temporary) / 'DEPENDENCIES.json'
            notice_path.write_bytes(notices)
            dependency_path.write_bytes(dependencies)
            name = 'switchboard_' + args.version + '_' + system + '_' + arch
            archive = output / (name + '.tar.gz')
            # Fixed timestamps and neutral owners avoid disclosing build-host
            # metadata and permit byte-for-byte repeated builds.
            with archive.open('wb') as raw:
                with gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
                    with tarfile.open(fileobj=compressed, mode='w') as tar:
                        for source, destination, mode in [(binary, 'switchboard', 0o755), (log_watcher_module, 'modules/switchboard-module-log-watcher', 0o755), (ROOT / 'README.md', 'README.md', 0o644), (ROOT / 'LICENSE', 'LICENSE', 0o644), (notice_path, notice_path.name, 0o644), (dependency_path, dependency_path.name, 0o644)]:
                            data = source.read_bytes()
                            entry = tarfile.TarInfo(name + '/' + destination)
                            entry.size, entry.mode, entry.mtime = len(data), mode, 0
                            tar.addfile(entry, io.BytesIO(data))
            hashes.append(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name)
    (output / 'SHA256SUMS').write_text('\n'.join(hashes) + '\n')
    print('Review archives created; publication still requires the privacy and licensing gates.')


if __name__ == '__main__':
    main()
