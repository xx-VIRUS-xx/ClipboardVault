import unittest

from core import classify_content, decrypt_text, encrypt_text, mask_secret


class CoreTests(unittest.TestCase):
    def test_secret_classification_masks_preview(self):
        result = classify_content("OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz123456")
        self.assertEqual(result.sensitivity, "high")
        self.assertIn("secret", result.tags)
        self.assertIn("...", result.masked_preview)

    def test_secret_summary_never_contains_the_secret(self):
        key = "sk-abcdefghijklmnopqrstuvwxyz123456"
        for content in (key, f"OPENAI_API_KEY={key}", f"{key}\nsecond line"):
            result = classify_content(content)
            self.assertEqual(result.sensitivity, "high")
            self.assertNotIn(key, result.summary)
            self.assertNotIn(key, result.masked_preview)
            self.assertIn("...", result.summary)

    def test_non_secret_summary_is_unchanged(self):
        result = classify_content("buy milk and eggs")
        self.assertEqual(result.summary, "buy milk and eggs")

    def test_json_credential_classification(self):
        result = classify_content('{"api_key": "abc123", "name": "demo"}')
        self.assertEqual(result.kind, "credential-json")
        self.assertEqual(result.sensitivity, "high")

    def test_encrypt_decrypt_round_trip(self):
        salt, ciphertext = encrypt_text("secret-value", "good-passphrase")
        self.assertEqual(decrypt_text(ciphertext, salt, "good-passphrase"), "secret-value")
        with self.assertRaises(ValueError):
            decrypt_text(ciphertext, salt, "bad-passphrase")

    def test_mask_secret_short_and_long(self):
        self.assertEqual(mask_secret("abcdef"), "******")
        self.assertEqual(mask_secret("abcdefghijklmnopqrstuvwxyz"), "abcdef...wxyz")


if __name__ == "__main__":
    unittest.main()
