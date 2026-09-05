"""Regression checks for the Week 6 provided secure implementation."""
import unittest

import jwt

import solution_app


class Week06SolutionTests(unittest.TestCase):
    def setUp(self):
        self.client = solution_app.app.test_client()
        login = self.client.post("/login", json={"user": "alice", "pw": "alicepw"})
        self.token = login.get_json()["token"]
        self.headers = {"Authorization": f"Bearer {self.token}"}

    def test_legitimate_owner_access_still_works(self):
        response = self.client.get("/api/orders/1", headers=self.headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["owner"], "alice")

    def test_cross_owner_idor_is_forbidden(self):
        response = self.client.get("/api/orders/2", headers=self.headers)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.get_json(), {"error": "forbidden"})

    def test_unsigned_and_weak_key_tokens_are_rejected(self):
        unsigned = jwt.encode({"sub": "bob"}, key="", algorithm="none")
        weak = jwt.encode({"sub": "bob"}, "secret", algorithm="HS256")
        for token in (unsigned, weak):
            response = self.client.get(
                "/api/orders/2", headers={"Authorization": f"Bearer {token}"}
            )
            self.assertEqual(response.status_code, 401)
            self.assertEqual(response.get_json(), {"error": "invalid token"})

    def test_forged_admin_is_rejected_and_real_user_is_forbidden(self):
        forged = jwt.encode({"sub": "admin"}, key="", algorithm="none")
        forged_response = self.client.get(
            "/api/admin", headers={"Authorization": f"Bearer {forged}"}
        )
        real_response = self.client.get("/api/admin", headers=self.headers)
        self.assertEqual(forged_response.status_code, 401)
        self.assertEqual(real_response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
