"""Collect verbatim dependency notices for a Go executable's target package graph."""
import hashlib
import json
from pathlib import Path
import re
import subprocess
from source_comments import collect as collect_assembly

NOTICE = re.compile(r'^(?:LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)(?:$|[._-])', re.I)


def json_stream(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        yield value
        raw = raw[end:]


def notice_files(root):
    root = Path(root)
    result = []
    for path in sorted(root.rglob('*')):
        if not NOTICE.match(path.name):
            continue
        if path.is_symlink():
            raise ValueError('dependency notice cannot be a symlink')
        if path.is_file():
            raw = path.read_bytes()
            raw.decode('utf-8')  # Fail for manual review rather than silently corrupting text.
            if not raw.strip():
                raise ValueError('empty dependency notice')
            result.append((path.relative_to(root).as_posix(), raw))
    if not result:
        raise ValueError('dependency has no discoverable notice files')
    return result


def collect(root, env, package='./cmd/switchboard', go_notices=None):
    packages = [package] if isinstance(package, str) else list(package)
    raw = subprocess.check_output(['go', 'list', '-mod=readonly', '-buildvcs=false', '-deps', '-json', *packages],
                                  cwd=root, env=env, text=True)
    modules = {}
    package_graph = list(json_stream(raw))
    for package_info in package_graph:
        module = package_info.get('Module')
        if module and not module.get('Main'):
            if module.get('Replace'):
                raise ValueError('release notices require unreplaced dependencies')
            modules[module['Path']] = module
    toolchain = json.loads(subprocess.check_output(['go', 'env', '-json', 'GOROOT', 'GOVERSION', 'GOHOSTOS', 'GOHOSTARCH'],
                                                 cwd=root, env=env, text=True))
    goroot = Path(toolchain['GOROOT'])
    # Generated dependencies can carry additional terms in source comments,
    # even when their root LICENSE covers the surrounding project. Use Go's
    # lexer so strings containing comment-like text are never treated as notices.
    inputs, assembly_inputs = [], []
    for info in package_graph:
        if 'Dir' not in info:
            continue
        directory = Path(info['Dir'])
        module = info.get('Module', {})
        if directory.is_relative_to(goroot / 'src'):
            component, base = 'Go toolchain', goroot / 'src'
        elif module and not module.get('Main'):
            component, base = module['Path'], Path(module.get('Dir', info['Root']))
        else:
            continue
        for name in info.get('GoFiles', []) + info.get('CgoFiles', []):
            path = directory / name
            inputs.append({'path': str(path), 'component': component,
                           'file': path.relative_to(base).as_posix()})
        for name in info.get('SFiles', []) + info.get('HFiles', []):
            path = directory / name
            assembly_inputs.append({'path': str(path), 'component': component,
                                    'file': path.relative_to(base).as_posix()})
    assembly_notices = collect_assembly(assembly_inputs)
    inputs.sort(key=lambda item: (item['component'], item['file']))
    host_env = dict(env, GOOS=toolchain['GOHOSTOS'], GOARCH=toolchain['GOHOSTARCH'])
    source_notices = json.loads(subprocess.check_output(
        ['go', 'run', '-mod=readonly', '-buildvcs=false', str(Path(root) / 'scripts/source-notices.go')],
        input=json.dumps(inputs), cwd=root, env=host_env, text=True))
    license_root = Path(go_notices) if go_notices else goroot
    files = [('LICENSE', (license_root / 'LICENSE').read_bytes())]
    if (license_root / 'PATENTS').is_file():
        files.append(('PATENTS', (license_root / 'PATENTS').read_bytes()))
    # Include nested toolchain and vendored notices conservatively, including
    # special standard-library implementations with additional attribution.
    files.extend(('src/' + name, data) for name, data in notice_files(goroot / 'src'))
    sources = [('Go toolchain', toolchain['GOVERSION'], '', files)]
    for name, module in sorted(modules.items()):
        if not module.get('Version') or not module.get('Sum'):
            raise ValueError('release dependency lacks a pinned version or checksum')
        sources.append((name, module['Version'], module['Sum'], notice_files(module['Dir'])))
    manifest = {'format': 1, 'target': env['GOOS'] + '/' + env['GOARCH'], 'components': []}
    sections = [b'Third-party notices\n\nVerbatim notice files from the compiled module graph and Go toolchain.\n'
                b'Nested module notices are included conservatively; this is not a license compatibility assessment.\n']
    for name, version, checksum, files in sources:
        if source_notices.get(name):
            files = files + [('SELECTED_GO_SOURCE_NOTICES.txt', source_notices[name].encode())]
        if assembly_notices.get(name):
            files = files + [('SELECTED_ASSEMBLY_HEADER_NOTICES.txt', assembly_notices[name])]
        entry = {'name': name, 'version': version, 'module_sum': checksum, 'notices': []}
        for relative, data in files:
            entry['notices'].append({'file': relative, 'sha256': hashlib.sha256(data).hexdigest()})
            sections.append(('\n===== ' + name + ' ' + version + ' / ' + relative + ' =====\n').encode() + data + b'\n')
        manifest['components'].append(entry)
    return b''.join(sections), (json.dumps(manifest, indent=2, sort_keys=True) + '\n').encode()
