import pytest
import requests
from requests.exceptions import RequestException, HTTPError, Timeout, ConnectionError
from utilities.read_config import ReadConfig


def send_request(method, endpoint, headers=None, payload=None, timeout=10):
    base_url = ReadConfig.get_base_url()
    url = f"{base_url}{endpoint}"

    try:
        response = requests.request(method, url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response
    except HTTPError as http_err:
        print(f"HTTP error occurred: {http_err}")
        pytest.fail(f"Test failed due to exception: {http_err}")
    except Timeout as timeout_err:
        print(f"Request timed out: {timeout_err}")
        raise
    except ConnectionError as conn_err:
        print(f"Connection error occurred: {conn_err}")
        raise
    except RequestException as req_err:
        print(f"An error occurred with the request: {req_err}")
        raise
