"""Regression checks for the Week 4 provided secure implementation."""
import io
import tempfile
import unittest
from pathlib import Path

import solution_app


class Week04SolutionTests(unittest.TestCase):
    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        root = Path(self.tempdir.name)
        solution_app.DB = str(root / "week04.db")
        solution_app.UPLOAD_DIR = str(root / "uploads")
        Path(solution_app.UPLOAD_DIR).mkdir()
        solution_app.seed()
        self.client = solution_app.app.test_client()

    def tearDown(self):
        self.tempdir.cleanup()

    def test_legitimate_login_still_works(self):
        response = self.client.get("/login", query_string={"user": "alice", "pw": "alicepw"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.text, "Welcome alice\n")

    def test_sql_injection_payloads_are_data(self):
        bypass = self.client.get(
            "/login", query_string={"user": "x' OR '1'='1'--", "pw": "x"}
        )
        dump = self.client.get(
            "/search",
            query_string={"q": "' UNION SELECT username,password FROM users--"},
        )
        self.assertEqual(bypass.text, "Login failed\n")
        self.assertNotIn("alicepw", dump.text)
        self.assertNotIn("bobpw", dump.text)

    def test_command_injection_is_rejected_before_subprocess(self):
        response = self.client.get("/ping", query_string={"host": "127.0.0.1;id"})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.text, "invalid host\n")

    def test_upload_allowlist_rejects_code_and_accepts_text(self):
        rejected = self.client.post(
            "/upload",
            data={"f": (io.BytesIO(b"print(1)\n"), "shell.py")},
            content_type="multipart/form-data",
        )
        accepted = self.client.post(
            "/upload",
            data={"f": (io.BytesIO(b"notes\n"), "../../notes.txt")},
            content_type="multipart/form-data",
        )
        self.assertEqual(rejected.status_code, 400)
        self.assertEqual(rejected.text, "file type not allowed\n")
        self.assertEqual(accepted.status_code, 200)
        self.assertTrue((Path(solution_app.UPLOAD_DIR) / "notes.txt").is_file())


if __name__ == "__main__":
    unittest.main()
