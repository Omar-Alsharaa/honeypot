import unittest
from honeypot import server

class TestChallenges(unittest.TestCase):
    def test_multipliers(self):
        base = server._simulate_vulnerability('show_flag')
        easy = server._simulate_vulnerability('show_flag','easy')
        hacker = server._simulate_vulnerability('show_flag','hacker')
        self.assertTrue(easy['points'] < base['points'])
        self.assertTrue(hacker['points'] > base['points'])

    def test_sqli_multiplier(self):
        normal = server._simulate_vulnerability("1' or 1=1 --","normal")
        hard = server._simulate_vulnerability("1' or 1=1 --","hard")
        self.assertTrue(hard['points'] > normal['points'])

if __name__ == '__main__':
    unittest.main()
