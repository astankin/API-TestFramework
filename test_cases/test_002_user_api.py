import json

import pytest

from utilities.helpers import generate_random_name, generate_random_password, generate_random_email
from utilities.read_config import ReadConfig
from utilities.request_handler import send_request


class TestUserAPI:
    all_users_endpoint = "users"
    register_user_endpoint = "users/register/"

    def test_get_users(self, base_url):
        bearer_token = ReadConfig.get_admin_token()
        headers = {
            "Content-Type": "application/json",
            "Authorization": bearer_token
        }

        try:
            response = send_request(method="GET",
                                    endpoint=self.all_users_endpoint,
                                    headers=headers
                                    )
            assert response.status_code == 200, "Expected 200 OK status code"
            data = response.json()
            print(json.dumps(data, indent=3))
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")

    def test_create_user(self):
        name = generate_random_name()
        email = generate_random_email()
        password = generate_random_password()
        payload = {
            "name": name,
            "email": email,
            "password": password
        }
        try:
            response = send_request(method="POST", endpoint=self.register_user_endpoint, payload=payload)
            data = response.json()
            assert response.status_code == 200, "Expected 200 Created status code"
            assert data["name"] == name, f"The response name: {data['name']} should match the payload {name}"
            assert data["username"] == email, f"Response username: {data['username']} should match the payload: {email}"
            assert data["email"] == email, f"Response email: {data['email']} should match the payload: {email}"
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")

