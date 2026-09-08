#!/usr/bin/env python3
"""Verify a local pi source bundle and install its pinned runtime dependencies."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    args = parser.parse_args()
    lines = (args.directory / 'SHA256SUMS').read_text().splitlines()
    assert len(lines) == 1, 'expected one source archive'
    digest, name = lines[0].split('  ', 1)
    assert Path(name).name == name and name.endswith('.tar.gz'), 'unsafe archive name'
    archive = args.directory / name
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest, 'archive checksum differs'
    prefix = name.removesuffix('.tar.gz')
    expected = {'index.ts', 'package.json', 'package-lock.json', 'README.md', 'LICENSE', 'DEPENDENCIES.json', 'THIRD_PARTY_NOTICES.txt'}
    with tarfile.open(archive) as tar:
        entries = tar.getmembers()
        assert len(entries) == len(expected) and {x.name for x in entries} == {prefix + '/' + x for x in expected}, 'unexpected bundle files'
        for entry in entries:
            assert entry.isfile() and entry.mode == 0o644 and entry.uid == 0 and entry.gid == 0 and entry.mtime == 0
            assert not entry.uname and not entry.gname, 'identifying archive metadata'
        payload = {file: tar.extractfile(prefix + '/' + file).read() for file in expected}
    package = json.loads(payload['package.json'])
    lock = json.loads(payload['package-lock.json'])
    manifest = json.loads(payload['DEPENDENCIES.json'])
    assert prefix == package['name'] + '_' + package['version']
    assert package['license'] == 'MIT' and package['private'] is True
    assert payload['LICENSE'].startswith(b'MIT License\n')
    assert manifest['format'] == 1
    runtime = {path: item for path, item in lock['packages'].items() if path and not item.get('dev')}
    components = manifest['components']
    assert len(components) == len(runtime) and {c['lock_path'] for c in components} == set(runtime), 'inventory differs from runtime lock graph'
    for component in components:
        locked = runtime[component['lock_path']]
        assert component['version'] == locked['version'] and component['integrity'] == locked['integrity']
        assert component['notices'], 'missing component notices'
        for notice in component['notices']:
            marker = ('\n===== ' + component['lock_path'] + ' / ' + notice['file'] + ' =====\n').encode()
            assert marker in payload['THIRD_PARTY_NOTICES.txt']
            raw = payload['THIRD_PARTY_NOTICES.txt'].split(marker, 1)[1].split(b'\n===== ', 1)[0]
            assert raw.endswith(b'\n') and hashlib.sha256(raw[:-1]).hexdigest() == notice['sha256'], 'notice text changed'
    with tempfile.TemporaryDirectory(prefix='switchboard-pi-install-') as tmp:
        stage = Path(tmp)
        for file, raw in payload.items():
            (stage / file).write_bytes(raw)
        subprocess.run(['npm', 'ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'], cwd=stage, check=True, stdout=subprocess.DEVNULL)
        for relative, entry in runtime.items():
            installed = json.loads((stage / relative / 'package.json').read_text())
            assert installed['version'] == entry['version'], 'installed version mismatch'
        subprocess.run(['node', '--input-type=module', '-e', 'import { Client } from "@modelcontextprotocol/sdk/client/index.js"; import { Agent } from "undici"; if (!Client || !Agent) process.exit(1)'], cwd=stage, check=True)
        assert not (stage / 'node_modules/jiti').exists(), 'development loader installed in runtime bundle'
    print('Pi source archive, full runtime inventory, notice hashes and clean locked dependency installation passed; intended pi host acceptance is separate.')


if __name__ == '__main__':
    main()
