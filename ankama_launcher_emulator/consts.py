import os

from ankama_launcher_emulator.interfaces.game_name_enum import GameNameEnum

DOFUS_PATH = os.path.join("D:\\", "Programmes", "Dofus-dofus3", "Dofus.exe")
ZAAP_PATH = os.path.join(os.environ["APPDATA"], "zaap")
CERTIFICATE_FOLDER_PATH = os.path.join(ZAAP_PATH, "certificate")
API_KEY_FOLDER_PATH = os.path.join(ZAAP_PATH, "keydata")

GAME_ID_BY_NAME: dict[GameNameEnum, str] = {GameNameEnum.DOFUS: "102"}
