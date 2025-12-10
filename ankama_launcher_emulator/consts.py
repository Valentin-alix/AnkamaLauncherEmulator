import json
import os


ZAAP_PATH = os.path.join(os.environ["APPDATA"], "zaap")

RELEASE_JSON_PATH = os.path.join(
    ZAAP_PATH, "repositories", "production", "dofus", "dofus3", "release.json"
)
with open(RELEASE_JSON_PATH, "r") as file:
    content = json.load(file)
    DOFUS_PATH = os.path.join(content["location"], "Dofus.exe")


CERTIFICATE_FOLDER_PATH = os.path.join(ZAAP_PATH, "certificate")
API_KEY_FOLDER_PATH = os.path.join(ZAAP_PATH, "keydata")
OFFICIAL_CONFIG_URL = r"https://dofus2.cdn.ankama.com/config/dofus3.json"
