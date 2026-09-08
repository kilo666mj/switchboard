#!/usr/bin/env python3
"""Create a local pi source review bundle with pinned runtime dependency notices."""
import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from release_notices import notice_files

ROOT = Path(__file__).resolve().parents[1]


def inventory(installed, lock):
    components, sections = [], [b'Pi runtime dependency notices\n\nVerbatim notices from a fresh npm ci --omit=dev --ignore-scripts installation.\nDependencies are not bundled; install from the included lockfile.\n']
    for relative, entry in sorted(lock['packages'].items()):
        if not relative or entry.get('dev'):
            continue
        parts = Path(relative).parts
        if not relative.startswith('node_modules/') or '..' in parts or Path(relative).is_absolute() or entry.get('link'):
            raise ValueError('unsupported lockfile package location')
        if not entry.get('integrity') or not entry.get('version'):
            raise ValueError('dependency lacks locked integrity or version')
        directory = installed / relative
        if not directory.is_dir() or directory.is_symlink():
            raise ValueError('locked runtime dependency is missing or linked')
        package = json.loads((directory / 'package.json').read_text())
        if package['version'] != entry['version']:
            raise ValueError('installed package differs from lockfile')
        component = {'name': package['name'], 'version': package['version'], 'lock_path': relative,
                     'integrity': entry['integrity'], 'declared_license': package.get('license'), 'notices': []}
        for name, data in notice_files(directory):
            component['notices'].append({'file': name, 'sha256': hashlib.sha256(data).hexdigest()})
            sections.append(('\n===== ' + relative + ' / ' + name + ' =====\n').encode() + data + b'\n')
        components.append(component)
    if not components:
        raise ValueError('empty runtime dependency inventory')
    return b''.join(sections), (json.dumps({'format': 1, 'install': 'npm ci --omit=dev --ignore-scripts',
                                           'components': components}, indent=2, sort_keys=True) + '\n').encode()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True, help='new output directory')
    args = parser.parse_args()
    source = ROOT / 'clients/pi'
    output = args.output.resolve()
    if output.exists():
        parser.error('output already exists; refusing to overwrite')
    output.mkdir(parents=True, mode=0o700)
    package = json.loads((source / 'package.json').read_text())
    lock = json.loads((source / 'package-lock.json').read_text())
    if lock.get('lockfileVersion') != 3 or lock['packages']['']['version'] != package['version']:
        raise ValueError('package and lockfile versions disagree')
    with tempfile.TemporaryDirectory(prefix='switchboard-pi-review-') as tmp:
        stage = Path(tmp)
        for name in ('package.json', 'package-lock.json'):
            (stage / name).write_bytes((source / name).read_bytes())
        # A fresh install validates registry integrity; no lifecycle scripts,
        # audit submission, or unrelated workspace packages are used.
        subprocess.run(['npm', 'ci', '--omit=dev', '--ignore-scripts', '--no-audit', '--no-fund'],
                       cwd=stage, check=True, stdout=subprocess.DEVNULL)
        notices, dependencies = inventory(stage, lock)
        payload = {name: (source / name).read_bytes() for name in ('index.ts', 'package.json', 'package-lock.json', 'README.md')}
        payload.update({'LICENSE': (ROOT / 'LICENSE').read_bytes(), 'THIRD_PARTY_NOTICES.txt': notices,
                        'DEPENDENCIES.json': dependencies})
        prefix = 'pi-extension-switchboard_' + package['version']
        archive = output / (prefix + '.tar.gz')
        with archive.open('wb') as raw, gzip.GzipFile(filename='', mode='wb', fileobj=raw, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode='w') as tar:
                for name, data in sorted(payload.items()):
                    entry = tarfile.TarInfo(prefix + '/' + name)
                    entry.size, entry.mode, entry.mtime = len(data), 0o644, 0
                    tar.addfile(entry, io.BytesIO(data))
        (output / 'SHA256SUMS').write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + '  ' + archive.name + '\n')
    print('Local pi source review bundle created; no dependencies bundled and nothing published.')


if __name__ == '__main__':
    main()
