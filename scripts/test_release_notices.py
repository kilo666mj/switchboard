from pathlib import Path
import tempfile
import unittest
from release_notices import json_stream, notice_files


class NoticeTest(unittest.TestCase):
    def test_missing_notice_fails_and_nested_notice_is_preserved(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            with self.assertRaisesRegex(ValueError, 'no discoverable notice'):
                notice_files(root)
            nested = root / 'third_party'
            nested.mkdir()
            (nested / 'NOTICE.txt').write_bytes(b'Nested attribution\r\n')
            (root / 'LICENSE').write_bytes(b'Top-level license\n')
            self.assertEqual(notice_files(root), [('LICENSE', b'Top-level license\n'),
                                                ('third_party/NOTICE.txt', b'Nested attribution\r\n')])
            (root / 'COPYING').symlink_to(root / 'LICENSE')
            with self.assertRaisesRegex(ValueError, 'symlink'):
                notice_files(root)

    def test_go_json_stream_has_multiple_objects(self):
        self.assertEqual(list(json_stream(' {"Path":"a"}\n {"Path":"b"}\n')), [{'Path': 'a'}, {'Path': 'b'}])
