import pytest

from utilities.helpers import generate_random_name, generate_random_email, generate_random_password
from utilities.request_handler import send_request


@pytest.fixture()
def create_user():
    """ Fixture to create a new user and return its details. """
    register_user_endpoint = "users/register/"
    name = generate_random_name()
    email = generate_random_email()
    password = generate_random_password()
    payload = {"name": name, "email": email, "password": password}
    response = send_request(method="POST", endpoint=register_user_endpoint, payload=payload)
    if response.status_code != 200: pytest.fail(
        f"User creation failed with status {response.status_code}: {response.text}")
    data = response.json()
    user_details = {"name": name, "username": data["username"], "email": email, "password": password, "id": data["id"]}
    return user_details