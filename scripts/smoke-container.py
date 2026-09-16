#!/usr/bin/env python3
"""Verify the native Switchboard container defaults and MCP startup."""
import argparse
import json
from pathlib import Path
import selectors
import subprocess
import tempfile


def verify_mcp(process, version, expected_tools=None):
    with selectors.DefaultSelector() as selector:
        selector.register(process.stdout, selectors.EVENT_READ)

        def rpc(identifier, method, params):
            process.stdin.write(json.dumps({
                'jsonrpc': '2.0', 'id': identifier, 'method': method, 'params': params,
            }) + '\n')
            process.stdin.flush()
            assert selector.select(timeout=10), 'container MCP response timed out'
            response = json.loads(process.stdout.readline())
            assert response.get('id') == identifier and 'error' not in response, 'MCP request failed'
            return response['result']

        initialized = rpc(1, 'initialize', {
            'protocolVersion': '2025-03-26', 'capabilities': {},
            'clientInfo': {'name': 'container-smoke', 'version': '1'},
        })
        assert initialized['serverInfo']['version'] == version, 'incorrect embedded version'
        process.stdin.write('{"jsonrpc":"2.0","method":"notifications/initialized"}\n')
        process.stdin.flush()
        catalog = rpc(2, 'tools/list', {})
        tools = {tool['name'] for tool in catalog.get('tools', [])}
        if expected_tools is not None:
            assert tools == expected_tools, 'incorrect tool catalog'
    process.stdin.close()
    if process.wait(timeout=10) != 0:
        raise RuntimeError(process.stderr.read())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('image')
    parser.add_argument('--version', required=True)
    args = parser.parse_args()

    metadata = json.loads(subprocess.check_output(
        ['docker', 'image', 'inspect', args.image], text=True))[0]['Config']
    assert metadata['User'] == '65532:65532', 'container must run as the non-root runtime user'
    assert metadata['Entrypoint'] == ['/usr/local/bin/switchboard'], 'unexpected entrypoint'
    assert metadata['Cmd'] == ['-config', '/etc/switchboard/switchboard.json'], 'unexpected default command'

    with tempfile.TemporaryDirectory(prefix='switchboard-container-') as temporary:
        root = Path(temporary)
        root.chmod(0o755)
        capabilities = root / 'capabilities'
        capabilities.mkdir(mode=0o755)
        config = root / 'switchboard.json'
        config.write_text(json.dumps({
            'transport': 'stdio',
            'profile': 'empty',
            'tool_policy': 'empty',
            'profiles': {'empty': []},
            'tool_policies': {
                'empty': {'version': 'container-smoke', 'profile': 'empty', 'capabilities': {}, 'tools': {}}
            },
            'egress_policy': {'allowed_destinations': [], 'allowed_cidrs': []},
            'capability_dir': '/etc/switchboard/capabilities',
        }))
        config.chmod(0o644)
        process = subprocess.Popen([
            'docker', 'run', '--rm', '-i', '--network', 'none', '--read-only',
            '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
            '--mount', f'type=bind,src={config},dst=/etc/switchboard/switchboard.json,readonly',
            '--mount', f'type=bind,src={capabilities},dst=/etc/switchboard/capabilities,readonly',
            args.image,
        ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            verify_mcp(process, args.version)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)

    module_policy = json.dumps({
        'allowed_destinations': ['127.0.0.1:1'],
        'allowed_cidrs': ['127.0.0.0/8'],
    })
    process = subprocess.Popen([
        'docker', 'run', '--rm', '-i', '--network', 'none', '--read-only',
        '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
        '--entrypoint', '/usr/local/libexec/switchboard/switchboard-module-log-watcher',
        '--env', 'SWITCHBOARD_MODULE_NAME=log_watcher',
        '--env', 'LOG_WATCHER_API_URL=https://127.0.0.1:1',
        '--env', 'LOG_WATCHER_API_TOKEN=container-smoke-placeholder',
        '--env', 'SWITCHBOARD_MODULE_EGRESS_POLICY=' + module_policy,
        args.image,
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        verify_mcp(process, args.version, {
            'log_watcher_list_excludes', 'log_watcher_add_exclude', 'log_watcher_remove_exclude',
        })
    finally:
        if process.poll() is None:
            process.kill()
            process.wait(timeout=5)
    print('Non-root, read-only, network-isolated gateway and module MCP startup passed.')


if __name__ == '__main__':
    main()
