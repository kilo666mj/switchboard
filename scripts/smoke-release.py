#!/usr/bin/env python3
"""Validate review archive hashes, metadata, and native binary startup commands."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import selectors
import tarfile
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path)
    parser.add_argument('--version', required=True)
    args = parser.parse_args()
    arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if platform.system() != 'Linux' or not arch:
        parser.error('native smoke verification requires Linux amd64 or arm64')
    native = None
    native_module = None
    hashes = (args.directory / 'SHA256SUMS').read_text().splitlines()
    assert hashes, 'empty checksum manifest'
    for line in hashes:
        digest, name = line.split('  ', 1)
        assert Path(name).name == name and name.endswith('.tar.gz'), 'unsafe archive name'
        archive = args.directory / name
        assert hashlib.sha256(archive.read_bytes()).hexdigest() == digest, 'checksum mismatch'
        with tarfile.open(archive, 'r:gz') as tar:
            entries = tar.getmembers()
            prefix = name.removesuffix('.tar.gz')
            expected = {'switchboard', 'modules/switchboard-module-log-watcher', 'README.md', 'LICENSE', 'THIRD_PARTY_NOTICES.txt', 'DEPENDENCIES.json'}
            assert len(entries) == len(expected) and {entry.name for entry in entries} == {prefix + '/' + file for file in expected}, 'unexpected archive contents'
            notices = tar.extractfile(prefix + '/THIRD_PARTY_NOTICES.txt').read()
            dependencies = json.load(tar.extractfile(prefix + '/DEPENDENCIES.json'))
            assert dependencies['format'] == 1 and dependencies['components'], 'missing dependency inventory'
            assert name.endswith('_' + dependencies['target'].replace('/', '_') + '.tar.gz'), 'wrong dependency target'
            for component in dependencies['components']:
                assert component['notices'], 'component missing notices'
                for notice in component['notices']:
                    marker = ('\n===== ' + component['name'] + ' ' + component['version'] + ' / ' + notice['file'] + ' =====\n').encode()
                    assert marker in notices, 'missing notice text'
                    data = notices.split(marker, 1)[1].split(b'\n===== ', 1)[0]
                    assert data.endswith(b'\n') and hashlib.sha256(data[:-1]).hexdigest() == notice['sha256'], 'notice content changed'
            license_text = tar.extractfile(prefix + '/LICENSE').read()
            assert license_text.startswith(b'MIT License\n') and b'Permission is hereby granted' in license_text, 'missing MIT license text'
            for entry in entries:
                assert entry.isfile() and entry.uid == 0 and entry.gid == 0 and entry.mtime == 0
                assert not entry.uname and not entry.gname, 'identifying archive metadata'
            binary = tar.getmember(prefix + '/switchboard')
            assert binary.mode == 0o755, 'binary is not executable'
            module = tar.getmember(prefix + '/modules/switchboard-module-log-watcher')
            assert module.mode == 0o755, 'module is not executable'
            if name.endswith('_linux_' + arch + '.tar.gz'):
                native = tar.extractfile(binary).read()
                native_module = tar.extractfile(module).read()
    assert native and native_module, 'no native archive to smoke test'
    with tempfile.TemporaryDirectory(prefix='switchboard-install-') as temporary:
        root = Path(temporary)
        binary = root / 'switchboard'
        binary.write_bytes(native)
        binary.chmod(0o755)
        # Empty stdio profile proves startup without contacting any upstream or
        # inheriting operator credentials. Verify the version through MCP itself.
        (root / 'capabilities').mkdir()
        config_path = root / 'switchboard.json'
        config_path.write_text(json.dumps({
            'transport': 'stdio',
            'profile': 'empty',
            'tool_policy': 'empty',
            'profiles': {'empty': []},
            'tool_policies': {
                'empty': {'version': 'release-smoke', 'profile': 'empty', 'capabilities': {}, 'tools': {}}
            },
            'egress_policy': {'allowed_destinations': [], 'allowed_cidrs': []},
            'capability_dir': 'capabilities',
        }))
        env = {'PATH': '/usr/bin:/bin', 'HOME': str(root), 'LANG': 'C.UTF-8'}
        subprocess.run([str(binary), '-help'], cwd=root, env=env, check=True, capture_output=True, timeout=10)
        process = subprocess.Popen([str(binary), '-config', str(config_path)], cwd=root, env=env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                def rpc(identifier, method, params):
                    process.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': identifier, 'method': method, 'params': params}) + '\n').encode())
                    process.stdin.flush()
                    assert selector.select(timeout=10), 'MCP response timed out'
                    response = json.loads(process.stdout.readline(1048577))
                    assert response.get('id') == identifier and 'error' not in response, 'MCP request failed'
                    return response['result']
                initialized = rpc(1, 'initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                                   'clientInfo': {'name': 'release-smoke', 'version': '1'}})
                assert initialized['serverInfo']['version'] == args.version, 'incorrect embedded version'
                process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
                process.stdin.flush()
                catalog = rpc(2, 'tools/list', {})
                assert isinstance(catalog.get('tools'), list), 'missing MCP tool catalog'
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
        module_binary = root / 'switchboard-module-log-watcher'
        module_binary.write_bytes(native_module)
        module_binary.chmod(0o755)
        module_env = {'PATH': '/usr/bin:/bin', 'LANG': 'C.UTF-8',
                      'SWITCHBOARD_MODULE_NAME': 'log_watcher',
                      'LOG_WATCHER_API_URL': 'https://127.0.0.1:1',
                      'LOG_WATCHER_API_TOKEN': 'release-smoke-placeholder',
                      'SWITCHBOARD_MODULE_EGRESS_POLICY': json.dumps({
                          'allowed_destinations': ['127.0.0.1:1'],
                          'allowed_cidrs': ['127.0.0.0/8'],
                      })}
        process = subprocess.Popen([str(module_binary)], cwd=root, env=module_env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        try:
            with selectors.DefaultSelector() as selector:
                selector.register(process.stdout, selectors.EVENT_READ)
                def module_rpc(identifier, method, params):
                    process.stdin.write((json.dumps({'jsonrpc': '2.0', 'id': identifier, 'method': method, 'params': params}) + '\n').encode())
                    process.stdin.flush()
                    assert selector.select(timeout=10), 'module MCP response timed out'
                    response = json.loads(process.stdout.readline(1048577))
                    assert response.get('id') == identifier and 'error' not in response, 'module MCP request failed'
                    return response['result']
                initialized = module_rpc(1, 'initialize', {'protocolVersion': '2025-03-26', 'capabilities': {},
                                                          'clientInfo': {'name': 'release-smoke', 'version': '1'}})
                assert initialized['serverInfo']['version'] == args.version, 'incorrect module version'
                process.stdin.write(b'{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
                process.stdin.flush()
                catalog = module_rpc(2, 'tools/list', {})
                assert {tool['name'] for tool in catalog['tools']} == {
                    'log_watcher_list_excludes', 'log_watcher_add_exclude', 'log_watcher_remove_exclude'
                }, 'incorrect module tool catalog'
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
    print('Archive hashes, neutral metadata, dependency notices, native MCP startup and embedded version passed.')



if __name__ == '__main__':
    main()
