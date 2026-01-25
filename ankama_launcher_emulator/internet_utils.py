import socket
import winreg
from time import sleep

import requests


def retry_internet(func):
    def wrapper(*args, **kwargs):
        try_count: int = 3
        while try_count > 0:
            try:
                return func(*args, **kwargs)
            except (
                requests.exceptions.ConnectionError,
                requests.exceptions.Timeout,
                socket.gaierror,
            ) as err:
                print(f"[NETWORK] Error: {err}. Retrying…")
                ensure_internet()
            try_count -= 1
            sleep(10)

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


def set_proxy(
    enable=True,
    proxy="127.0.0.1:8080",
    exceptions="https://api.openai.com",
):
    """
    Configure le proxy Windows pour l'utilisateur courant.
    enable : True pour activer, False pour désactiver
    proxy : adresse:port du proxy
    exceptions : liste des adresses à exclure, séparées par ';'
    """
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    with winreg.OpenKey(
        winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE
    ) as key:
        winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if enable:
            winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, proxy)
            winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, exceptions)
    print(f"Proxy {'activé' if enable else 'désactivé'}")
