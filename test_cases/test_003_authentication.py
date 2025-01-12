from utilities.request_handler import send_request


class TestAuthentication:
    def test_login_with_invalid_credentials(self):
        payload = {
            "username": "nonexistentuser@example.com",
            "password": "wrongpassword"
        }
        response = send_request(method="POST", endpoint="users/login/", payload=payload)
        assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"
        response_data = response.json()
        assert "detail" in response_data and response_data["detail"] == "Invalid credentials"

    def test_access_protected_route_without_token(self):
        response = send_request(method="GET", endpoint=self.all_users_endpoint)
        assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"

    def test_access_protected_route_with_invalid_token(self):
        headers = {"Authorization": "Bearer invalid_token"}
        response = send_request(method="GET", endpoint=self.all_users_endpoint, headers=headers)
        assert response.status_code == 401, f"Expected 401 Unauthorized, got {response.status_code}"


