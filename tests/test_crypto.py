import unittest
import cryptovault

class TestCryptoVault(unittest.TestCase):
    def test_password_entropy_calculation(self):
        # A 20-character mixed password has high entropy
        pwd = cryptovault.generate_password(20)
        entropy = cryptovault.calculate_entropy(pwd)
        self.assertGreater(entropy, 90.0)

    def test_strength_assessment(self):
        assessment = cryptovault.assess_strength('P@ssw0rd2026!SecureKey')
        self.assertIn('entropy_bits', assessment)
        self.assertTrue(assessment['has_upper'])
        self.assertTrue(assessment['has_lower'])
        self.assertTrue(assessment['has_digit'])
        self.assertTrue(assessment['has_symbol'])

    def test_key_derivation_reproducibility(self):
        salt = cryptovault.os.urandom(16)
        key1 = cryptovault.derive_key('MasterSecretKey123', salt)
        key2 = cryptovault.derive_key('MasterSecretKey123', salt)
        self.assertEqual(key1, key2)

if __name__ == '__main__':
    unittest.main()
