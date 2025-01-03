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


