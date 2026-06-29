import unittest
from unittest.mock import patch

from argon2 import PasswordHasher
from fastapi import HTTPException

from src.backend.routers import auth


class LoginTests(unittest.TestCase):
    def test_login_accepts_valid_argon2_password(self):
        teacher = {
            "_id": "mchen",
            "username": "mchen",
            "display_name": "Mr. Chen",
            "password": PasswordHasher().hash("chess456"),
            "role": "teacher",
        }

        with patch.object(auth.teachers_collection, "find_one", return_value=teacher):
            response = auth.login("mchen", "chess456")

        self.assertEqual(response["username"], "mchen")
        self.assertEqual(response["display_name"], "Mr. Chen")
        self.assertEqual(response["role"], "teacher")

    def test_login_rejects_invalid_password(self):
        teacher = {
            "_id": "mchen",
            "username": "mchen",
            "display_name": "Mr. Chen",
            "password": PasswordHasher().hash("chess456"),
            "role": "teacher",
        }

        with patch.object(auth.teachers_collection, "find_one", return_value=teacher):
            with self.assertRaises(HTTPException) as context:
                auth.login("mchen", "wrong-password")

        self.assertEqual(context.exception.status_code, 401)


if __name__ == "__main__":
    unittest.main()
