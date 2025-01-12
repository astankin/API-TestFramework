import pytest
import requests
from requests.exceptions import RequestException, HTTPError, Timeout, ConnectionError

from utilities.logger import setup_logger
from utilities.read_config import ReadConfig


def send_request(method, endpoint, headers=None, payload=None, timeout=10):

    """ Sends an HTTP request and returns the response.
    :param method: HTTP method (GET, POST, PUT, DELETE, etc.)
    :param endpoint: API endpoint
    :param headers: HTTP headers
    :param payload: JSON payload
    :param timeout: Request timeout
    :return: Response object
    :raises: HTTPError, Timeout, ConnectionError, RequestException
    """
    logger = setup_logger(log_file_path="../logs/products_api.log")
    base_url = ReadConfig.get_base_url()
    url = f"{base_url}{endpoint}"

    try:
        response = requests.request(method, url, headers=headers, json=payload, timeout=timeout)
        response.raise_for_status()
        return response
    except HTTPError as http_err:
        logger.error(f"HTTP error occurred: {http_err}")
    except Timeout as timeout_err:
        logger.error(f"Request timed out: {timeout_err}")
        raise
    except ConnectionError as conn_err:
        logger.error(f"Connection error occurred: {conn_err}")
        raise
    except RequestException as req_err:
        logger.error(f"An error occurred with the request: {req_err}")
        raise
