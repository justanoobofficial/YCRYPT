import tempfile
import unittest
from pathlib import Path

from ycrypt.crypto import encrypt_file, decrypt_file, verify_file, YcryptError


class CryptoWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.folder = Path(self.temp.name)
        self.source = self.folder / "sample.txt"
        self.source.write_bytes((b"YCRYPT local test data\n" * 5000))
        self.encrypted = self.folder / "sample.txt.ycrypt"
        self.recovered = self.folder / "recovered.txt"
        self.password = "a-long-test-passphrase"

    def tearDown(self):
        self.temp.cleanup()

    def test_round_trip_and_metadata(self):
        encrypt_file(self.source, self.encrypted, self.password)
        metadata = verify_file(self.encrypted, self.password)
        decrypt_file(self.encrypted, self.recovered, self.password)
        self.assertEqual(self.source.read_bytes(), self.recovered.read_bytes())
        self.assertEqual(metadata["name"], self.source.name)
        self.assertEqual(metadata["size"], self.source.stat().st_size)

    def test_wrong_password_rejected(self):
        encrypt_file(self.source, self.encrypted, self.password)
        with self.assertRaises(YcryptError):
            verify_file(self.encrypted, "not-the-password")

    def test_tampering_rejected(self):
        encrypt_file(self.source, self.encrypted, self.password)
        data = bytearray(self.encrypted.read_bytes())
        data[-20] ^= 0x01
        damaged = self.folder / "damaged.ycrypt"
        damaged.write_bytes(data)
        with self.assertRaises(YcryptError):
            verify_file(damaged, self.password)

    def test_output_is_not_overwritten(self):
        encrypt_file(self.source, self.encrypted, self.password)
        with self.assertRaises(YcryptError):
            encrypt_file(self.source, self.encrypted, self.password)


if __name__ == "__main__":
    unittest.main()
