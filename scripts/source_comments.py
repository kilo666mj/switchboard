"""Preserve license-bearing C-style comments from selected assembly and headers."""
from pathlib import Path, PurePosixPath
import re

NOTICE = re.compile(rb'copyright|licen[cs]|permission|redistribut|public\s+domain|spdx', re.I)


def comment_spans(raw):
    """Locate C comments while skipping string and character literals."""
    i = 0
    while i < len(raw):
        if raw[i:i+2] == b'/*':
            end = raw.find(b'*/', i+2)
            if end < 0:
                raise ValueError('unterminated source comment')
            yield i, end+2
            i = end+2
        elif raw[i:i+2] == b'//':
            start = i
            while True:
                end = raw.find(b'\n', i+1)
                if end < 0:
                    end = len(raw)
                    break
                if raw[start:end].rstrip(b'\r').endswith(b'\\'):
                    i = end
                    continue
                break
            yield start, end
            i = end
        elif raw[i:i+1] in (b'"', b"'"):
            quote = raw[i]
            i += 1
            while i < len(raw):
                if raw[i] == 92:  # escaped character
                    i += 2
                elif raw[i] == quote:
                    i += 1
                    break
                else:
                    i += 1
        else:
            i += 1


def c_comments(raw):
    """Preserve complete adjacent comment groups, including unmarked term lines."""
    start, end = None, 0
    for next_start, next_end in comment_spans(raw):
        if start is not None and raw[end:next_start].strip():
            yield raw[start:end]
            start = None
        if start is None:
            start = next_start
        end = next_end
    if start is not None:
        yield raw[start:end]


def collect(inputs):
    result = {}
    for item in sorted(inputs, key=lambda value: (value['component'], value['file'])):
        path, relative = Path(item['path']), PurePosixPath(item['file'])
        if path.is_symlink() or not path.is_file() or relative.is_absolute() or '..' in relative.parts:
            raise ValueError('unsafe selected source notice input')
        raw = path.read_bytes()
        raw.decode('utf-8')
        for group in c_comments(raw):
            if NOTICE.search(group):
                section = b'\n--- ' + relative.as_posix().encode() + b' ---\n' + group + b'\n'
                result[item['component']] = result.get(item['component'], b'') + section
    return result
