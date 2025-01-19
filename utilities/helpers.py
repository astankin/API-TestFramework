import random
import string

import pytest
import requests
from requests import RequestException

from utilities.request_handler import send_request


def generate_random_name():
    def random_string(length):
        characters = string.ascii_letters
        return ''.join(random.choice(characters) for _ in range(length))

    first_name = random_string(random.randint(4, 8)).capitalize()
    last_name = random_string(random.randint(4, 10)).capitalize()
    return f"{first_name} {last_name}"


def generate_random_password(length=10):
    lowercase = random.choice(string.ascii_lowercase)
    uppercase = random.choice(string.ascii_uppercase)
    digit = random.choice(string.digits)
    special_char = random.choice("@$!%*?&")  # Only allow specific special characters
    required_chars = [lowercase, uppercase, digit, special_char]

    all_characters = string.ascii_letters + string.digits + "!@#$%"
    remaining_chars = [random.choice(all_characters) for _ in range(length - 4)]
    password_list = required_chars + remaining_chars
    random.shuffle(password_list)
    return ''.join(password_list)

def generate_random_email():
    username = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
    email_domains = ['gmail.com', 'yahoo.com', 'hotmail.com', 'example.com', 'yourdomain.com']
    domain = random.choice(email_domains)
    email = f"{username}@{domain}"
    return email

def get_user_token(username=None, password=None):
    if not username or not password:
        raise ValueError("Username and password must be provided.")

    url = "http://127.0.0.1:8000/api/users/login/"
    credentials = {
        "username": username,
        "password": password
    }

    try:
        response = requests.post(url, data=credentials, timeout=10)
        response.raise_for_status()  # Raise an exception for HTTP errors

        data = response.json()  # Parse the JSON response
        token = data.get("token")

        if not token:
            raise ValueError("Token not found in the response.")

        return token

    except RequestException as e:
        print(f"Error making request to {url}: {e}")
        raise
    except ValueError as e:
        print(f"Error: {e}")
        raise



