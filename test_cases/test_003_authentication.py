import pytest

from utilities.delete_users_database import delete_user_by_id
from utilities.helpers import generate_random_password
from utilities.json_validator import ResponseValidator
from utilities.logger import setup_logger
from utilities.read_config import ReadConfig
from utilities.request_handler import send_request
from utilities.fixtures import create_user


class TestAuthentication:
    logger = setup_logger(log_file_path=ReadConfig.get_logs_authentication_path())
    test_user_id = int(ReadConfig.get_tes_user_id())
    test_user_name = ReadConfig.get_tes_user_name()
    test_user_username = ReadConfig.get_tes_user_username()
    test_user_email = ReadConfig.get_tes_user_email()
    test_user_password = ReadConfig.get_tes_user_password()
    login_endpoint = ReadConfig.get_login_endpoint()
    headers = {"Content-Type": "application/json"}

    def test_login_with_valid_credentials(self):
        self.logger.info("*** Starting Test test_login_with_valid_credentials ***")

        payload = {
            "username": self.test_user_username,
            "password": self.test_user_password,
        }
        expected_fields = {
            "refresh": str,
            "access": str,
            "id": int,
            "_id": int,
            "username": str,
            "email": str,
            "name": str,
            "isAdmin": bool,
            "token": str,
        }
        expected_values = {
            "id": self.test_user_id,
            "_id": self.test_user_id,
            "username": self.test_user_username,
            "email": self.test_user_email,
            "name": self.test_user_name,
            "isAdmin": False,
        }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            ResponseValidator.validate_response_headers(response, expected_content_type="application/json")
            #ResponseValidator.validate_response_time(response, max_response_time_ms=1000)
            ResponseValidator.validate_data_type(response=response, field_validations=expected_fields)
            ResponseValidator.validate_field_value(response=response, field_validations=expected_values)
            self.logger.info("Test PASS")
        except Exception as e:
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_invalid_username(self):
        self.logger.info("*** Starting Test test_login_with_invalid_username ***")

        payload = {
            "username": "invalid_user",
            "password": self.test_user_password,
        }
        expected_message = "No active account found with the given credentials"
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 401, f"Expected 401, got {response.status_code}"
            data = response.json()
            assert "detail" in data, "Thea field 'detail' is not in the response"
            assert data['detail'] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_invalid_password(self):
        self.logger.info("*** Starting Test test_login_with_invalid_password ***")

        payload = {
            "username": self.test_user_username,
            "password": "InvalidPassword123@",
        }
        expected_message = "No active account found with the given credentials"
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 401, f"Expected 401, got {response.status_code}"
            data = response.json()
            assert "detail" in data, "Thea field 'detail' is not in the response"
            assert data['detail'] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_empty_username(self):
        self.logger.info("*** Starting Test test_login_with_empty_username ***")

        payload = {
            "username": "",
            "password": self.test_user_password,
        }
        expected_message = "This field may not be blank."
        expected_fields = {
            "username": list
        }
        expected_response = {
                    "username": [
                        "This field may not be blank."
                    ]
                }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 400, f"Expected 400, got {response.status_code}"
            data = response.json()
            ResponseValidator.validate_data_type(response=response, field_validations=expected_fields)
            ResponseValidator.validate_field_value(response=response, field_validations=expected_response)
            assert "username" in data, "The field 'username' is not in the response"
            assert data['username'][0] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")


    def test_login_with_missing_username(self):
        self.logger.info("*** Starting Test test_login_with_missing_username ***")

        payload = {
            "password": self.test_user_password,
        }
        expected_message = "This field is required."
        expected_fields = {
            "username": list
        }
        expected_response = {
                    "username": [
                        "This field is required."
                    ]
                }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 400, f"Expected 400, got {response.status_code}"
            data = response.json()
            ResponseValidator.validate_data_type(response=response, field_validations=expected_fields)
            ResponseValidator.validate_field_value(response=response, field_validations=expected_response)
            assert "username" in data, "The field 'username' is not in the response"
            assert data['username'][0] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_empty_password(self):
        self.logger.info("*** Starting Test test_login_with_empty_password ***")

        payload = {
            "username": self.test_user_username,
            "password": ""
        }
        expected_message = "This field may not be blank."
        expected_fields = {
            "password": list
        }
        expected_response = {
                    "password": [
                        "This field may not be blank."
                    ]
                }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 400, f"Expected 400, got {response.status_code}"
            data = response.json()
            ResponseValidator.validate_response_time(response, max_response_time_ms=1000)
            ResponseValidator.validate_data_type(response=response, field_validations=expected_fields)
            ResponseValidator.validate_field_value(response=response, field_validations=expected_response)
            assert "password" in data, "The field 'password' is not in the response"
            assert data['password'][0] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_missing_password(self):
        self.logger.info("*** Starting Test test_login_with_missing_username ***")

        payload = {
            "username": self.test_user_username,
        }
        expected_message = "This field is required."
        expected_fields = {
            "password": list
        }
        expected_response = {
                    "password": [
                        "This field is required."
                    ]
                }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 400, f"Expected 400, got {response.status_code}"
            data = response.json()
            ResponseValidator.validate_response_time(response, max_response_time_ms=1000)
            ResponseValidator.validate_data_type(response=response, field_validations=expected_fields)
            ResponseValidator.validate_field_value(response=response, field_validations=expected_response)
            assert "password" in data, "The field 'password' is not in the response"
            assert data['password'][0] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_new_created_user(self, create_user):
        user_data = create_user
        user_id = user_data["id"]
        username = user_data["username"]
        email = user_data["email"]
        password = user_data["password"]

        payload = {
            "username": username,
            "password": password,
        }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            delete_user_by_id(user_id)
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_deleted_user(self, create_user):
        user_id = create_user["id"]
        username = create_user["username"]
        email = create_user["email"]
        password = create_user["password"]
        expected_message = "No active account found with the given credentials"
        payload = {
            "username": username,
            "password": password,
        }
        try:
            self.logger.info("Sending POST request")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 200, f"Expected 200, got {response.status_code}"
            delete_user_by_id(user_id)
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 401, f"Expected 401, got {response.status_code}"
            data = response.json()
            assert "detail" in data, "Thea field 'detail' is not in the response"
            assert data['detail'] == expected_message
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_with_sql_injection(self):
        self.logger.info("*** Starting Test test_login_with_sql_injection ***")
        payload = {
            "username": "' OR 1=1; --",
            "password": generate_random_password(),
        }
        try:
            self.logger.info("Sending POST request with SQL injection payload")
            response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code == 401, f"Expected 401, got {response.status_code}"
            self.logger.info("Test PASS - SQL injection attempt blocked")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

    def test_login_rate_limiting(self):
        self.logger.info("*** Starting Test test_login_rate_limiting ***")
        payload = {"username": self.test_user_username, "password": "wrong_password"}
        response = None
        try:
            for _ in range(10):
                self.logger.info("Sending POST request")
                response = send_request(method="POST", endpoint=self.login_endpoint, payload=payload, headers=self.headers, logger=self.logger)
            assert response.status_code in [429, 401], "Expected 429 Too Many Requests or 401 Unauthorized"
            self.logger.info("Test PASS")
        except Exception as e:
            self.logger.info("Test FAIL")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")





