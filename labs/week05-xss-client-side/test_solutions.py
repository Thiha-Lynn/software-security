"""Regression checks for the provided and completed Week 5 defenses."""
import re
import unittest

import fixed_app
import student_solution


class ProvidedFixTests(unittest.TestCase):
    def setUp(self):
        fixed_app.COMMENTS.clear()
        self.client = fixed_app.app.test_client()

    def test_xss_is_escaped_and_headers_are_present(self):
        reflected = self.client.get("/hello", query_string={"name": "<script>alert(1)</script>"})
        stored = self.client.post("/comments", data={"body": "<script>alert(1)</script>"})
        root = self.client.get("/")
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", reflected.data)
        self.assertIn(b"&lt;script&gt;alert(1)&lt;/script&gt;", stored.data)
        self.assertIn("script-src 'self'", reflected.headers["Content-Security-Policy"])
        cookie = root.headers["Set-Cookie"]
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Secure", cookie)

    def test_worksheet_described_csrf_gap_remains_in_provided_fix(self):
        forged = self.client.post("/comments", data={"body": "forged without token"})
        self.assertEqual(forged.status_code, 200)
        self.assertIn(b"forged without token", forged.data)


class CompletedStudentSolutionTests(unittest.TestCase):
    def setUp(self):
        student_solution.COMMENTS.clear()
        self.client = student_solution.app.test_client()

    def test_missing_csrf_token_is_rejected(self):
        forged = self.client.post("/comments", data={"body": "forged without token"})
        self.assertEqual(forged.status_code, 403)
        self.assertNotIn("forged without token", student_solution.COMMENTS)

    def test_token_from_another_session_is_rejected(self):
        attacker = student_solution.app.test_client()
        form = attacker.get("/comments")
        token = re.search(rb'name=csrf_token value="([^"]+)"', form.data).group(1).decode()
        self.client.get("/comments")
        forged = self.client.post("/comments", data={"csrf_token": token, "body": "cross-session forgery"})
        self.assertEqual(forged.status_code, 403)
        self.assertNotIn("cross-session forgery", student_solution.COMMENTS)

    def test_token_without_its_session_cookie_is_rejected(self):
        form = self.client.get("/comments")
        token = re.search(rb'name=csrf_token value="([^"]+)"', form.data).group(1).decode()
        anonymous = student_solution.app.test_client(use_cookies=False)
        forged = anonymous.post("/comments", data={"csrf_token": token, "body": "no session"})
        self.assertEqual(forged.status_code, 403)

    def test_malformed_token_is_rejected_without_server_error(self):
        self.client.get("/comments")
        forged = self.client.post("/comments", data={"csrf_token": "invalid-\u2603", "body": "malformed"})
        self.assertEqual(forged.status_code, 403)

    def test_session_cookie_and_security_headers(self):
        response = self.client.get("/")
        cookie = response.headers["Set-Cookie"]
        for flag in ("HttpOnly", "SameSite=Strict", "Secure", "wk05_session="):
            self.assertIn(flag, cookie)
        self.assertIn("form-action 'self'", response.headers["Content-Security-Policy"])

    def test_valid_token_allows_normal_post_and_output_is_escaped(self):
        form = self.client.get("/comments")
        token = re.search(rb'name=csrf_token value="([^"]+)"', form.data).group(1).decode()
        accepted = self.client.post(
            "/comments",
            data={"csrf_token": token, "body": "<img src=x onerror=alert(1)>"},
        )
        self.assertEqual(accepted.status_code, 200)
        self.assertIn(b"&lt;img src=x onerror=alert(1)&gt;", accepted.data)
        self.assertNotIn(b"<img src=x", accepted.data)


if __name__ == "__main__":
    unittest.main()
