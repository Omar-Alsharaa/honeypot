import unittest
from honeypot import server

class TestSimulation(unittest.TestCase):
    def test_flag_trigger(self):
        out = server._simulate_vulnerability('show_flag')
        self.assertTrue(out.get('exposed_flag'))
        self.assertEqual(out.get('vuln'), 'flag')

    def test_sqli(self):
        out = server._simulate_vulnerability("1' OR 1=1 --")
        self.assertEqual(out.get('vuln'), 'sqlinjection')
        self.assertGreater(out.get('points',0), 0)

    def test_lfi(self):
        out = server._simulate_vulnerability('../../etc/passwd')
        self.assertEqual(out.get('vuln'), 'lfi')

    def test_rce_marker(self):
        out = server._simulate_vulnerability('; ls')
        self.assertEqual(out.get('vuln'), 'rce')

if __name__ == '__main__':
    unittest.main()
