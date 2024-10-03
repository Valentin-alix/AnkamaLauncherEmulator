from dataclasses import dataclass

from src.haapi.haapi import Haapi


@dataclass
class AccountGameInfo:
    login: str
    gameId: str
    api_key: str
    haapi: Haapi
