import base64
import hashlib
import json
import os
from pathlib import Path
import random
import shutil


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


def generate_code_verifier() -> str:
    ### Native method from Ankama launcher
    code_length = int(85 * random.random() + 43)
    allowed_characters = (
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    code_verifier = ""
    for _ in range(code_length):
        code_verifier += allowed_characters[
            int(random.random() * len(allowed_characters))
        ]
    return code_verifier


def create_code_challenge(code_verifier: str) -> str:
    ### Native method from Ankama launcher
    hash_object = hashlib.sha256(code_verifier.encode())
    hash_digest = hash_object.digest()
    base64_encoded = base64.urlsafe_b64encode(hash_digest).decode("utf-8")
    code_challenge = base64_encoded.rstrip("=").replace("+", "-").replace("/", "_")
    return code_challenge
