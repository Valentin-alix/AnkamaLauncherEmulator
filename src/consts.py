import os
from pathlib import Path


DOFUS_PATH = os.path.join(os.getenv("LOCALAPPDATA", ""), "Ankama", "Dofus", "Dofus.exe")

TOKENS_PATH = os.path.join(Path(__file__).parent.parent, "resources", "tokens.json")

try:
    os.makedirs(TOKENS_PATH, exist_ok=True)
except FileExistsError:
    pass
