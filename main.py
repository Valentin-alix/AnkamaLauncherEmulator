import sys

from tokens import get_token


def start_thrift_server(): ...


if __name__ == "__main__":
    start_thrift_server()
    sys.exit()
    token = get_token("hello-terre@outlook.fr", "doftemp448")
    response = f"auth_getGameToken {token}\0"
    print(response)
