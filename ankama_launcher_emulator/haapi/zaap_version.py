import json
import os
import shutil
from pathlib import Path


def get_zaap_version():
    temp_path = "tmp"
    os.makedirs(temp_path, exist_ok=True)

    # Extract launcher on tmp dir
    os.system(
        f'asar extract "{os.path.join(os.getenv('programfiles', ''), 'Ankama', 'Ankama Launcher','resources', 'app.asar')}" "{Path(temp_path).absolute()}"'
    )

    # Find launcher version
    zaapVersion = "none"
    with open(os.path.join(temp_path, "package.json")) as jsonFile:
        disctJson = json.load(jsonFile)
        zaapVersion = disctJson.get("version")

    # Remove tmp folder
    shutil.rmtree(temp_path)

    if zaapVersion == "none":
        zaapVersion = "3.12.19"
    return zaapVersion


ZAAP_VERSION = get_zaap_version()
