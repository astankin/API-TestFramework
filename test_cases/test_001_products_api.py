
import pytest
from selenium.webdriver.common.bidi.cdp import logger

from utilities.json_validator import  ResponseValidator
from utilities.logger import setup_logger
from utilities.read_config import ReadConfig
from utilities.request_handler import send_request
from utilities.schema_loader import load_json_schema


class TestProductAPI:
    logger = setup_logger(log_file_path=ReadConfig.get_logs_product_path())
    products_endpoint = ReadConfig.get_products_endpoint()
    product_id = 1
    product_schema = load_json_schema("product_schema.json")
    all_product_schema = load_json_schema("all_products_schema.json")

    def test_get_products_list(self):
        headers = {'Content-Type': 'application/json'}
        self.logger.info("*** Starting test: test_get_products_list ***")
        try:
            self.logger.info(f"Sending GET request to {self.products_endpoint}")
            response = send_request(method="GET",
                                    endpoint=self.products_endpoint,
                                    headers=headers,
                                    logger=self.logger
                                    )
            self.logger.info("Validating response status code")
            assert response.status_code == 200, "Expected 200 OK status code"
            ResponseValidator.validate_response_headers(response, expected_content_type="application/json")
            ResponseValidator.validate_response_time(response)
            self.logger.info("Validating response all products json schema")
            ResponseValidator.validate_json_schema(response=response, schema=self.all_product_schema)
            data = response.json()
            self.logger.info("*** Test test_get_products_list completed successfully ***")
        except Exception as e:
            self.logger.info("*** Test test_get_products_list Failed ***")
            pytest.fail(f"Test failed due to exception: {e}")

    def test_get_product_by_id(self):
        headers = {'Content-Type': 'application/json'}
        self.logger.info("*** Starting test: test_get_product_by_id ***")
        try:
            self.logger.info(f"Sending GET request to {self.products_endpoint}{self.product_id}")
            response = send_request(method="GET",
                                    endpoint=f'{self.products_endpoint}/{self.product_id}',
                                    headers=headers,
                                    logger=self.logger
                                    )
            expected_fields = {
                                "_id": int,
                                "reviews": list,
                                "name": str,
                                "image": str,
                                "brand": str,
                                "category": str,
                                "description": str,
                                "rating": str,
                                "numReviews": int,
                                "price": str,
                                "countInStock": int,
                                "createdAt": str,
                                "user": int
                            }
            expected_values = {
                                "_id": 1,
                                "name": "Airpods Wireless Bluetooth Headphones",
                                "image": "/images/airpods_rueLkRx.jpg",
                                "brand": "Apple",
                                "category": "Electronics",
                                "description": "Bluetooth technology lets you connect it with compatible devices wirelessly High-quality AAC audio offers immersive listening experience Built-in microphone allows you to take calls while working",
                                "rating": "3.00",
                                "numReviews": 2,
                                "price": "1998.99",
                                "countInStock": 18,
                                "createdAt": "2024-08-13T19:30:16.537131Z",
                                "user": 1
                                }
            self.logger.info("Validating response status code")
            assert response.status_code == 200, "Expected 200 OK status code"
            self.logger.info("Validating response headers")
            ResponseValidator.validate_response_headers(response=response, expected_content_type="application/json")
            self.logger.info("Validating response time")
            ResponseValidator.validate_response_time(response=response)
            self.logger.info("Validating response product json schema")
            ResponseValidator.validate_json_schema(response=response, schema=self.product_schema)
            self.logger.info("Validating response data fields type")
            ResponseValidator.validate_data_type(response=response,
                                                 field_validations=expected_fields)
            self.logger.info("Validating response fields value")
            ResponseValidator.validate_field_value(response=response,
                                                   field_validations=expected_values)
            self.logger.info("*** Test test_get_product_by_id completed successfully ***")
        except Exception as e:
            self.logger.info("*** Test test_get_product_by_id Failed ***")
            pytest.fail(f"Test failed due to exception: {e}")

    def test_create_product(self):
        headers = {'Content-Type': 'application/json'}
        payload = {
            "name": "Test Product",
            "image": "/images/test_product.jpg",
            "brand": "Test Brand",
            "category": "Test Category",
            "description": "This is a test product description.",
            "price": "123.45",
            "countInStock": 10
        }
        self.logger.info("*** Starting test: test_create_product ***")
        try:
            self.logger.info(f"Sending POST request to {self.products_endpoint}")
            response = send_request(method="POST",
                                    endpoint=self.products_endpoint,
                                    headers=headers,
                                    payload=payload,
                                    logger=self.logger,
                                    )
            self.logger.info("Validating response status code")
            assert response.status_code == 200, "Expected 200 Created status code"
            self.logger.info("Validating response product json schema")
            ResponseValidator.validate_json_schema(response=response, schema=self.product_schema)
            data = response.json()
            self.logger.info("*** Test test_create_product completed successfully ***")
        except Exception as e:
            self.logger.info("*** Test test_create_product Failed ***")
            pytest.fail(f"Test failed due to exception: {e}")
        finally:
            self.logger.info("*** Test Finished ***")

