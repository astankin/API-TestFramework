import json
import os

def load_json_schema(schema_name):
    schema_dir = os.path.join(os.path.dirname(__file__), "../schemas")
    schema_path = os.path.join(schema_dir, schema_name)
    with open(schema_path, 'r') as file:
        return json.load(file)
