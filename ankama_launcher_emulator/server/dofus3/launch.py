import os
import subprocess

from ankama_launcher_emulator.consts import DOFUS_PATH
from ankama_launcher_emulator.interfaces.game_name_enum import GameNameEnum


def launch_dofus_exe(instance_id: int, random_hash: str, connection_port: int) -> int:
    log_path = os.path.join(
        os.environ["LOCALAPPDATA"],
        "Roaming",
        "zaap",
        "gamesLogs",
        "dofus-dofus3",
        "dofus.log",
    )
    command = [
        DOFUS_PATH,
        "--port",
        "26116",
        "--gameName",
        GameNameEnum.DOFUS.value,
        "--gameRelease",
        "dofus3",
        "--instanceId",
        str(instance_id),
        "--hash",
        random_hash,
        "--canLogin",
        "true",
        "-logFile",
        log_path,
        "--langCode",
        "fr",
        "--autoConnectType",
        "2",
        "--connectionPort",
        str(connection_port),
    ]

    env = {
        "ZAAP_CAN_AUTH": "true",
        "ZAAP_GAME": GameNameEnum.DOFUS.value,
        "ZAAP_HASH": random_hash,
        "ZAAP_INSTANCE_ID": str(instance_id),
        "ZAAP_LOGS_PATH": log_path,
        "ZAAP_PORT": "26116",
        "ZAAP_RELEASE": "dofus3",
    }

    process = subprocess.Popen(
        command,
        env=os.environ.copy() | env,
        start_new_session=True,
        cwd=os.path.dirname(command[0]),
    )
    return process.pid
