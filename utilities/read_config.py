import configparser
import os

config_path = os.path.join(os.path.dirname(__file__), '..', 'configurations', 'config.ini')

config = configparser.RawConfigParser()
config.read(config_path)

class ReadConfig:
    @staticmethod
    def get_base_url():
        url = config.get(section='common', option='base_url')
        return url

    @staticmethod
    def get_admin_token():
        admin_token = config.get(section='common', option='admin_token')
        return admin_token

    @staticmethod
    def get_tes_user_name():
        test_user_name = config.get(section='test_user_account', option='test_user_name')
        return test_user_name

    @staticmethod
    def get_tes_user_id():
        test_user_id = config.get(section='test_user_account', option='test_user_id')
        return test_user_id

    @staticmethod
    def get_tes_user_email():
        test_user_email = config.get(section='test_user_account', option='test_user_email')
        return test_user_email

    @staticmethod
    def get_tes_user_username():
        test_user_username = config.get(section='test_user_account', option='test_user_username')
        return test_user_username

    @staticmethod
    def get_tes_user_password():
        test_user_password = config.get(section='test_user_account', option='test_user_password')
        return test_user_password

    @staticmethod
    def get_login_endpoint():
        return config.get(section='end_points', option='login_endpoint')

    @staticmethod
    def get_register_user_endpoint():
        return config.get(section='end_points', option='register_user_endpoint')

    @staticmethod
    def get_users_endpoint():
        return config.get(section='end_points', option='users_endpoint')

    @staticmethod
    def get_edit_user_endpoint():
        return config.get(section='end_points', option='edit_user_endpoint')

    @staticmethod
    def get_delete_user_endpoint():
        return config.get(section='end_points', option='delete_user_endpoint')

    @staticmethod
    def get_products_endpoint():
        return config.get(section='end_points', option='products_endpoint')

    @staticmethod
    def get_logs_users_path():
        return config.get(section='logger', option='logs_user_path')

    @staticmethod
    def get_logs_authentication_path():
        return config.get(section='logger', option='logs_authentication_path')

    @staticmethod
    def get_logs_product_path():
        return config.get(section='logger', option='logs_product_path')
