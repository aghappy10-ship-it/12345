import unittest
from tools.menu_inputs import validate_pair, verify_current_pair, PROJECT, GUI
from tools.qt_unit import read_main_screen
from tools.build_unit import build, DEVICE_URL


class MenuInputTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.original = read_main_screen(GUI)
        cls.host = build(cls.original, (PROJECT / 'qml/X2d2MenuBootstrap.qml').as_uri())
        cls.device = build(cls.original, DEVICE_URL)

    def test_exact_host_and_device_pair(self):
        result = validate_pair(self.original, self.host, self.device)
        self.assertTrue(result['sameOriginalBytecode'])

    def test_stale_host_url_rejected_despite_valid_checksum(self):
        wrong = build(self.original, 'file:///F:/some-older-project/Bootstrap.qml')
        with self.assertRaises(ValueError): validate_pair(self.original, wrong, self.device)

    def test_stale_device_url_rejected_despite_valid_checksum(self):
        wrong = build(self.original, 'file:///system/etc/OtherBootstrap.qml')
        with self.assertRaises(ValueError): validate_pair(self.original, self.host, wrong)


if __name__ == '__main__': unittest.main()
