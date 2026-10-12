import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from tools.output_guard import PROJECT, guard_output, output_directory, write_output


class OutputGuardTests(unittest.TestCase):
    def setUp(self):
        output_directory(PROJECT / 'build')
        self.temp = tempfile.TemporaryDirectory(prefix='guard-', dir=PROJECT / 'build')
        self.root = Path(self.temp.name)

    def tearDown(self): self.temp.cleanup()

    def test_roundtrip_and_replace_new_inode(self):
        path = self.root / 'nested/test.bin'
        write_output(path, b'one', self.root)
        write_output(path, b'two', self.root)
        self.assertEqual(path.read_bytes(), b'two')
        self.assertEqual(list(path.parent.glob('*.tmp')), [])

    def test_outside_or_broad_root_rejected(self):
        with self.assertRaises(ValueError): guard_output(PROJECT / 'src/forbidden.bin')
        with self.assertRaises(ValueError): guard_output(self.root / 'x', PROJECT)
        with self.assertRaises(ValueError): guard_output(self.root / '../x', self.root)
        with self.assertRaises(ValueError): guard_output(PROJECT / 'src/forbidden.bin', PROJECT / 'src')
        with self.assertRaises(ValueError): guard_output(PROJECT / 'work/forbidden.bin', PROJECT / 'work')

    def test_hardlinked_destination_rejected_without_changing_either_file(self):
        original = self.root / 'original'; original.write_bytes(b'original')
        alias = self.root / 'alias'; os.link(original, alias)
        try:
            with self.assertRaises(ValueError): write_output(alias, b'bad', self.root)
            self.assertEqual(original.read_bytes(), b'original')
        finally: alias.unlink()

    def test_redirected_trust_root_and_ancestor_rejected(self):
        destination = self.root / 'safe'; destination.mkdir()
        link = self.root / 'linked'
        # NTFS junction creation needs no admin privilege. The target remains
        # wholly inside this temporary test directory and is never recursively removed.
        if os.name == 'nt':
            result = subprocess.run(['cmd', '/c', 'mklink', '/J', str(link), str(destination)],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        else: link.symlink_to(destination, target_is_directory=True)
        try:
            with self.assertRaises(ValueError): guard_output(link / 'x', link)
            with self.assertRaises(ValueError): write_output(link / 'nested/x', b'bad', self.root)
            self.assertEqual(list(destination.iterdir()), [])
        finally:
            if os.name == 'nt': os.rmdir(link)
            else: link.unlink()


if __name__ == '__main__': unittest.main()
