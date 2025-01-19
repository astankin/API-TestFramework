import pytest
from utilities.helpers import generate_random_name, generate_random_password, generate_random_email, get_user_token
from utilities.json_validator import ResponseValidator
from utilities.logger import setup_logger
from utilities.read_config import ReadConfig
from utilities.request_handler import send_request
from utilities.fixtures import create_user


class TestUserAPI:
    BASE_HEADERS = {"Content-Type": "application/json"}
    all_users_endpoint = ReadConfig.get_users_endpoint()
    register_user_endpoint = ReadConfig.get_register_user_endpoint()
    edit_user_endpoint = ReadConfig.get_edit_user_endpoint()
    get_user_endpoint = ReadConfig.get_users_endpoint()
    delete_user_endpoint = ReadConfig.get_delete_user_endpoint()
    admin_bearer_token = ReadConfig.get_admin_token()
    logger = setup_logger(log_file_path=ReadConfig.get_logs_users_path())


    @staticmethod
    def tear_down(admin_token, user_id, endpoint):
        """
        Deletes a user by ID using the given admin token and endpoint.
        """
        headers = {
            "Content-Type": "application/json",
            "Authorization": admin_token
        }
        end_point = f"{endpoint}{user_id}/"
        try:
            delete_response = send_request(method="DELETE", endpoint=end_point, headers=headers)
            assert delete_response.status_code in [200, 204], f"Failed to delete user {user_id}. Response: {delete_response.text}"
        except Exception as e:
            TestUserAPI.logger.error(f"Tear down failed for user {user_id}. Exception: {e}")
            raise


    def test_get_users(self, base_url):
        headers = {**self.BASE_HEADERS, "Authorization": self.admin_bearer_token}
        self.logger.info("*** Starting test_get_users ***")
        try:
            self.logger.info("Sending GET request")
            response = send_request(method="GET",
                                    endpoint=self.all_users_endpoint,
                                    headers=headers,
                                    logger=self.logger
                                    )
            assert response.status_code == 200, "Expected 200 OK status code"
            ResponseValidator.validate_response_headers(response, expected_content_type="application/json")
            ResponseValidator.validate_response_time(response)
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_get_user_by_id(self, create_user):
        """
        Tests retrieving a user by ID and ensures that the user exists with correct details.
        """
        self.logger.info("*** Start test_get_user_by_id ***")
        name = create_user['name']
        username = create_user['email']
        email = create_user['email']
        user_id = create_user['id']
        headers = {**self.BASE_HEADERS, "Authorization": self.admin_bearer_token}

        try:
            self.logger.info("Sending GET request")
            response = send_request(method="GET", endpoint=f"{self.get_user_endpoint}/{user_id}", headers=headers, logger=self.logger)
            assert response.status_code == 200, f"Expected 200 OK, got {response.status_code}"
            ResponseValidator.validate_response_headers(response, expected_content_type="application/json")
            ResponseValidator.validate_response_time(response)

            expected_fields = {
                "_id": int,
                "username": str,
                "email": str,
                "name": str,
                "isAdmin": bool,
            }
            expected_values = {
                "_id": user_id,
                "username": username,
                "email": email,
                "name": name,
                "isAdmin": False,
            }

            ResponseValidator.validate_data_type(response=response, field_validations=expected_fields)
            ResponseValidator.validate_field_value(response=response, field_validations=expected_values)
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("Delete user")
            TestUserAPI.tear_down(admin_token=self.admin_bearer_token, user_id=user_id, endpoint=self.delete_user_endpoint)
            self.logger.info("*** Test Finished ***")

    def test_get_user_with_invalid_id(self):
        self.logger.info("*** Starting test_get_user_with_invalid_id ***")
        headers = {"Authorization": self.admin_bearer_token}
        response = None
        try:
            response = send_request(method="GET", endpoint=f"{self.get_user_endpoint}invalid-id", headers=headers, logger=self.logger)
        except Exception:
            self.logger.info("Test PASS")
            assert response.status_code == 500, f"Expected 500 Bad Request, got {response.status_code}"
        finally:
            self.logger.info("*** Test Finished ***")

    def test_create_user(self):
        self.logger.info("*** Started test_create_user ***")
        name = generate_random_name()
        email = generate_random_email()
        password = generate_random_password()
        new_user_id = None
        payload = {
            "name": name,
            "email": email,
            "password": password
        }
        try:
            self.logger.info("Sending POST Request")
            response = send_request(method="POST", endpoint=self.register_user_endpoint, payload=payload, logger=self.logger)
            data = response.json()
            new_user_id = data['id']
            assert response.status_code == 200, "Expected 200 Created status code"
            assert data["name"] == name, f"The response name: {data['name']} should match the payload {name}"
            assert data["username"] == email, f"Response username: {data['username']} should match the payload: {email}"
            assert data["email"] == email, f"Response email: {data['email']} should match the payload: {email}"
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            if new_user_id:
                self.logger.info("Delete new user")
                TestUserAPI.tear_down(admin_token=self.admin_bearer_token, user_id=new_user_id, endpoint=self.delete_user_endpoint)
            self.logger.info("*** Test Finished ***")

    def test_create_user_with_duplicate_email(self, create_user):
        self.logger.info("*** Starting test_create_user_with_duplicate_email ***")
        payload = {
            "name": "Duplicate User",
            "email": create_user["email"],
            "password": "newpassword123"
        }
        response = None
        user_id = create_user['id']
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.register_user_endpoint, payload=payload, logger=self.logger)
        except Exception:
            assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"
            data = response.json()
            user_id = data['id']
            assert "User with this email already exists" == data['detail'], "Error message should include details about the duplicate email"
            self.logger.info("TEST PASS")
        finally:
            self.logger.info("Delete new user")
            if user_id:
                TestUserAPI.tear_down(admin_token=self.admin_bearer_token, user_id=user_id, endpoint=self.delete_user_endpoint)
            self.logger.info("*** Test Finished ***")

    def test_create_user_with_invalid_email(self):
        self.logger.info("*** Starting  test_create_user_with_invalid_email ***")
        payload = {
            "name": "Invalid Email",
            "email": generate_random_name(),
            "password": "password123"
        }
        user_id = None
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.register_user_endpoint, payload=payload, logger=self.logger)
            data = response.json()
            if response.status_code == 200:
                user_id = data['id']
            assert response.status_code == 400, f"Expected 400 Bad Request, got {response.status_code}"
            assert "email" in data, "Error message should mention invalid email format"
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            if user_id:
                self.logger.info("Delete new user")
                TestUserAPI.tear_down(admin_token=self.admin_bearer_token, user_id=user_id, endpoint=self.delete_user_endpoint)
            self.logger.info("*** Test Finished ***")


    def test_edit_user_with_valid_data(self, create_user):
        self.logger.info("*** Starting test_edit_user_with_valid_data ***")
        user_id = create_user['id']
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
            self.logger.info("Sending PUT request")
            response = send_request(method="PUT", endpoint=self.edit_user_endpoint, headers=header, payload=payload, logger=self.logger)
            data = response.json()
            assert response.status_code == 200, "Expected 200 Created status code"
            assert data["name"] == edited_name, f"The response name: {data['name']} should match the payload {edited_name}"
            assert data["username"] == email, f"Response username: {data['username']} should match the payload: {email}"
            assert data["email"] == email, f"Response email: {data['email']} should match the payload: {email}"
            self.logger.info("Test PASS")
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")
            self.logger.info("Test FAIL")
        finally:
            if user_id:
                self.logger.info("Delete new user")
                TestUserAPI.tear_down(admin_token=self.admin_bearer_token, user_id=user_id, endpoint=self.delete_user_endpoint)
            self.logger.info("*** Test Finished ***")

    def test_edit_user_with_invalid_data(self, create_user):
        self.logger.info("*** Starting test_edit_user_with_invalid_data ***")
        user_id = create_user['id']
        user_token = get_user_token(username=create_user["email"], password=create_user["password"])
        headers = {"Authorization": f"Bearer {user_token}"}
        payload = {"name": ""}
        response = None
        try:
            self.logger.info("Sending PUT request")
            response = send_request(method="PUT", endpoint=self.edit_user_endpoint, headers=headers, payload=payload, logger=self.logger)
        except Exception:
            self.logger.info("Test PASS")
            assert response.status_code == 500, f"Expected 500 Bad Request, got {response.status_code}"
        finally:
            if user_id:
                self.logger.info("Delete new user")
                TestUserAPI.tear_down(admin_token=self.admin_bearer_token, user_id=user_id, endpoint=self.delete_user_endpoint)
            self.logger.info("*** Test Finished ***")

    def test_delete_user(self, create_user):
        self.logger.info("*** Starting test_delete_user ***")
        user_id = create_user['id']
        headers = {
            "Content-Type": "application/json",
            "Authorization": self.admin_bearer_token
        }
        end_point = f"{self.delete_user_endpoint}{user_id}/"
        try:
            self.logger.info("Sending DELETE request")
            delete_response = send_request(method="DELETE", endpoint=end_point, headers=headers, logger=self.logger)
            message = delete_response.json()
            assert delete_response.status_code in [200, 204], "Expected 200 Created status code"
            assert message == "User was deleted"
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FALL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_delete_non_existent_user(self):
        self.logger.info("*** Starting test_delete_non_existent_user ***")
        non_existent_user_id = 99999
        headers = {"Authorization": self.admin_bearer_token}
        endpoint = f"{self.delete_user_endpoint}{non_existent_user_id}/"
        try:
            self.logger.info("Sending DELETE request")
            response = send_request(method="DELETE", endpoint=endpoint, headers=headers, logger=self.logger)
        except Exception:
            assert response.status_code == 500, f"Expected 500 Not Found, got {response.status_code}"
            self.logger.info("Test PASS ***")
        finally:
            self.logger.info("*** Test Finished ***")

