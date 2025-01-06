import json
import time

import pytest
import requests

from utilities.helpers import generate_random_name, generate_random_password, generate_random_email, get_user_token
from utilities.json_validator import ResponseValidator
from utilities.read_config import ReadConfig
from utilities.request_handler import send_request


class TestUserAPI:
    all_users_endpoint = "users"
    register_user_endpoint = "users/register/"
    edit_user_endpoint = "users/profile/update/"
    get_user_endpoint = "users/"
    delete_user_endpoint = "users/delete/"
    admin_bearer_token = ReadConfig.get_admin_token()

    @pytest.fixture()
    def create_user(self):
        """
        Fixture to create a new user and return its details.
        """
        name = generate_random_name()
        email = generate_random_email()
        password = generate_random_password()
        payload = {
            "name": name,
            "email": email,
            "password": password
        }
        response = send_request(method="POST", endpoint=self.register_user_endpoint, payload=payload)
        if response.status_code != 200:
            pytest.fail(f"User creation failed with status {response.status_code}: {response.text}")
        data = response.json()
        return {
            "name": name,
            "email": email,
            "password": password,
            "id": data["id"]
        }

    def test_get_users(self, base_url):
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.admin_bearer_token
        }

        try:
            response = send_request(method="GET",
                                    endpoint=self.all_users_endpoint,
                                    headers=headers
                                    )
            assert response.status_code == 200, "Expected 200 OK status code"
            ResponseValidator.validate_response_headers(response, expected_content_type="application/json")
            ResponseValidator.validate_response_time(response)

        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")

    def test_get_user_by_id(self, create_user):
        name = create_user['name']
        username = create_user['email']
        password = create_user['password']
        email = create_user['email']
        user_id = create_user['id']
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.admin_bearer_token
        }

        try:
            response = send_request(method="GET", endpoint=f"{self.get_user_endpoint}{user_id}", headers=headers)
            assert response.status_code == 200, "Expected 200 OK status code"
            ResponseValidator.validate_response_headers(response, expected_content_type="application/json")
            ResponseValidator.validate_response_time(response)
            ResponseValidator.validate_data_type(response=response,
                                                 field_validations={
                                                     "_id": int,
                                                     "username": str,
                                                     "email": str,
                                                     "name": str,
                                                     "isAdmin": bool,
                                                 })
            ResponseValidator.validate_field_value(response=response,
                                                   field_validations={
                                                       "_id": user_id,
                                                       "username": username,
                                                       "email": email,
                                                       "name": name,
                                                       "isAdmin": False,
                                                   })
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")

    def test_create_user(self):
        self.name = generate_random_name()
        self.email = generate_random_email()
        self.password = generate_random_password()
        payload = {
            "name": self.name,
            "email": self.email,
            "password": self.password
        }
        try:
            response = send_request(method="POST", endpoint=self.register_user_endpoint, payload=payload)
            data = response.json()
            self.new_user_id = data['id']
            assert response.status_code == 200, "Expected 200 Created status code"
            assert data["name"] == self.name, f"The response name: {data['name']} should match the payload {self.name}"
            assert data["username"] == self.email, f"Response username: {data['username']} should match the payload: {self.email}"
            assert data["email"] == self.email, f"Response email: {data['email']} should match the payload: {self.email}"
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")

    def test_edit_user(self, create_user):
        username = create_user['email']
        password = create_user['password']
        email = create_user['email']
        user_token = get_user_token(username=username, password=password)
        header = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {user_token}"
        }
        edited_name = f"User Python Edited"
        payload = {
            "name": edited_name,
            "email": email,
            "password": "",
        }
        try:
            response = send_request(method="PUT", endpoint=self.edit_user_endpoint, headers=header, payload=payload)
            data = response.json()
            assert response.status_code == 200, "Expected 200 Created status code"
            assert data["name"] == edited_name, f"The response name: {data['name']} should match the payload {edited_name}"
            assert data["username"] == email, f"Response username: {data['username']} should match the payload: {email}"
            assert data["email"] == email, f"Response email: {data['email']} should match the payload: {email}"
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")



    def test_delete_user(self, create_user):
        user_id = create_user['id']
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.admin_bearer_token
        }
        end_point = f"{self.delete_user_endpoint}{user_id}/"
        try:
            delete_response = send_request(method="DELETE", endpoint=end_point, headers=headers)
            message = delete_response.json()
            assert delete_response.status_code in [200, 204], "Expected 200 Created status code"
            assert message == "User was deleted"
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")