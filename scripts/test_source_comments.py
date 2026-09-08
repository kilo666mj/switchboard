from pathlib import Path
import tempfile
import unittest
from source_comments import collect, c_comments


class SourceCommentsTest(unittest.TestCase):
    def test_assembly_notice_preserves_all_terms_and_excludes_literals(self):
        notice = (b'// Copyright Example Authors\r\n//\r\n'
                  b'// Permission is hereby granted.\r\n'
                  b'// Keep this complete condition and disclaimer.\r\n')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'copy.s'
            path.write_bytes(notice + b'#include "textflag.h"\n'
                             b'DATA text<>+0(SB)/8, $"// Copyright is a string"\n'
                             b'/* ordinary implementation note */\n')
            result = collect([{'path': str(path), 'component': 'runtime', 'file': 'runtime/copy.s'}])
            self.assertEqual(result, {'runtime': b'\n--- runtime/copy.s ---\n' + notice})
            self.assertNotIn(tmp.encode(), result['runtime'])

    def test_block_comments_and_header_continuations(self):
        raw = b'#define STR "/* Copyright literal */"\n/* Copyright A\n * All terms. */\n// License\\\n continued\nint x;'
        self.assertEqual(list(c_comments(raw)), [b'/* Copyright A\n * All terms. */\n// License\\\n continued'])

    def test_malformed_and_linked_sources_fail(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / 'source.h'
            item = {'path': str(path), 'component': 'runtime', 'file': 'source.h'}
            path.write_bytes(b'/* Copyright missing end')
            with self.assertRaises(ValueError):
                collect([item])
            path.unlink()
            path.symlink_to('/dev/null')
            with self.assertRaisesRegex(ValueError, 'unsafe'):
                collect([item])
