
import unittest
from analyzer import find_top_ip


class TestLogAnalyzer(unittest.TestCase):

    def test_find_top_ip(self):
        ip_count = {
            "192.168.1.10": 5,
            "192.168.1.20": 4,
            "192.168.1.30": 3
        }

        top_ip, top_count = find_top_ip(ip_count)

        self.assertEqual(top_ip, "192.168.1.10")
        self.assertEqual(top_count, 5)

    def test_empty_ip_count(self):
        top_ip, top_count = find_top_ip({})

        self.assertIsNone(top_ip)
        self.assertEqual(top_count, 0)


if __name__ == "__main__":
    unittest.main()
