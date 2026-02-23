import json
import os

if os.name == "nt":
    ZAAP_PATH = os.path.join(os.environ["APPDATA"], "zaap")
else:
    config_home = os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config"))
    ZAAP_PATH = os.path.join(config_home, "zaap")

RELEASE_JSON_PATH = os.path.join(
    ZAAP_PATH, "repositories", "production", "dofus", "dofus3", "release.json"
)
if os.path.exists(RELEASE_JSON_PATH):
    with open(RELEASE_JSON_PATH, "r") as file:
        content = json.load(file)
        DOFUS_PATH = os.path.join(
            content["location"], "Dofus.exe" if os.name == "nt" else "Dofus"
        )
else:
    DOFUS_PATH = "DUMMY_PATH"
    print("<!> No Dofus path found !")
DOFUS_INSTALLED = os.path.exists(DOFUS_PATH)


RETRO_RELEASE_JSON_PATH = os.path.join(
    ZAAP_PATH, "repositories", "production", "retro", "main", "release.json"
)
if os.path.exists(RETRO_RELEASE_JSON_PATH):
    with open(RETRO_RELEASE_JSON_PATH, "r") as file:
        content = json.load(file)
        RETRO_PATH = os.path.join(
            content["location"], "Dofus Retro.exe" if os.name == "nt" else "DofusRetro"
        )
else:
    RETRO_PATH = "DUMMY_RETRO_PATH"
    print("<!> No Retro path found !")
RETRO_INSTALLED = os.path.exists(RETRO_PATH)


CERTIFICATE_FOLDER_PATH = os.path.join(ZAAP_PATH, "certificate")
API_KEY_FOLDER_PATH = os.path.join(ZAAP_PATH, "keydata")

SETTINGS_PATH = os.path.join(ZAAP_PATH, "Settings")


PROXY_URL = "http://c11dfd1d285080f6:NnU2okrD@185.162.130.85:10000"
LAUNCHER_PORT = 26116

GITHUB_URL = "https://github.com/Valentin-alix/AnkamaLauncherEmulatorProxy"

if os.name == "nt":
    _app_config_dir = os.path.join(os.environ["APPDATA"], "AnkamaLauncherEmulatorProxy")
else:
    _app_config_dir = os.path.join(
        os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")),
        "AnkamaLauncherEmulatorProxy",
    )
os.makedirs(_app_config_dir, exist_ok=True)
APP_CONFIG_PATH = os.path.join(_app_config_dir, "config.json")
