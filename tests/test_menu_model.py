import subprocess
import sys
import unittest
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]


class MenuModelTests(unittest.TestCase):
    def test_real_qt_behavior_in_isolated_process(self):
        completed = subprocess.run([sys.executable, '-B', str(PROJECT / 'tools/check_menu_model.py')],
                                   capture_output=True, text=True, encoding='utf-8', timeout=60)
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)
        self.assertIn('"result": "PASS"', completed.stdout)


if __name__ == '__main__': unittest.main()
