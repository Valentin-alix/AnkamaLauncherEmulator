from dataclasses import dataclass


@dataclass
class AccountGameInfo:
    login: str
    password: str
    gameId: str
    api_key: str
