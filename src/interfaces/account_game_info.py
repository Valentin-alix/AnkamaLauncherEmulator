from dataclasses import dataclass

from src.haapi.haapi import Haapi


@dataclass
class AccountGameInfo:
    login: str
    game_id: str
    api_key: str
    haapi: Haapi
