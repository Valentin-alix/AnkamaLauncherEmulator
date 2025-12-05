import socket
from time import sleep


def retry_internet(func):
    def wrapper(*args, **kwargs):
        while True:
            try:
                return func(*args, **kwargs)
            except Exception as err:
                print(f"[NETWORK] Error: {err}. Retrying…")
                ensure_internet()

    return wrapper


def ensure_internet(wait=1):
    while not has_internet_connection():
        print("[WARN] No internet, waiting...")
        sleep(wait)


def has_internet_connection(host="www.google.com", port=80, timeout=5) -> bool:
    """
    Host: www.google.com
    OpenPort: 80/tcp
    Service: domain (DNS/TCP)
    """
    try:
        conn = socket.create_connection((host, port), timeout)
        conn.close()
        return True
    except socket.error:
        return False
