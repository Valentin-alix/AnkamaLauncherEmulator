import socket
import sys

from tokens import get_token



# C:\\Users\\valen\\AppData\\Local\\Ankama\\Dofus\\Dofus.exe --port=26116 --gameName=dofus --gameRelease=main --instanceId=1 --hash=e8ba6925-a61b-455c-bac3-3f4192296627 --canLogin=true

if __name__ == "__main__":
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 26117))
    sock.listen(1)
    print("la")
    client_sock, addr = sock.accept()
    print("here")
    # buffer = client_sock.recv(4086)
    # print("Received data:", buffer)

    token = get_token("yokoufer357", "huhugi357!")
    response = f"auth_getGameToken {token}\0"
    print(response)
    # send to client
    client_sock.sendall(response.encode('utf-8'))

    client_sock.close()
    sock.close()