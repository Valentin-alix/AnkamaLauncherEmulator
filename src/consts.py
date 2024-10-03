import os


DOFUS_PATH = os.path.join(os.getenv("LOCALAPPDATA", ""), "Ankama", "Dofus", "Dofus.exe")
ZAAP_PATH = os.path.join(os.environ["APPDATA"], "zaap")
CERTIFICATE_FOLDER_PATH = os.path.join(ZAAP_PATH, "certificate")
API_KEY_FOLDER_PATH = os.path.join(ZAAP_PATH, "keydata")
GAME_ID_BY_NAME: dict[str, str] = {"dofus": "102"}
