import configparser
import os

path = os.path.expanduser("~/.aws/credentials")
parser = configparser.ConfigParser()
read_files = parser.read(path)

if not read_files:
    print("no credentials file found")
elif "default" in parser and "aws_access_key_id" in parser["default"]:
    print("credentials file looks valid")
else:
    print("credentials file is missing required fields")
