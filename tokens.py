import random
import hashlib
import base64
import json
from bs4 import BeautifulSoup
import requests

#### RE by SuperJudeFruit

def generate_code_verifier():
    ### Native method from Ankama launcher
    e = int(85 * random.random() + 43)
    t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    n = ""
    for r in range(e):
        n += t[int(random.random() * len(t))]
    return n

def create_code_challenge(e):
    ### Native method from Ankama launcher
    hash_object = hashlib.sha256(e.encode())
    hash_digest = hash_object.digest()
    base64_encoded = base64.urlsafe_b64encode(hash_digest).decode('utf-8')
    code_challenge = base64_encoded.rstrip('=').replace('+', '-').replace('/', '_')
    return code_challenge

def getStateFromBrowser(codeChallenge, clientId):
    url = 'https://auth.ankama.com/login/ankama?code_challenge=' + str(codeChallenge) + '&redirect_uri=zaap://login&client_id=' + clientId + '&direct=true&origin_tracker=https://www.ankama-launcher.com/launcher'
    payload = {}

    headers = {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br, zstd',
      'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
      'Cache-Control': 'max-age=0',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36'
    }

    response = requests.get(url, headers=headers, data=payload)
    soup = BeautifulSoup(response.content, "html.parser")

    result = soup.find("input", {"name": "state"})['value']
    return result

def getCodeFromBrowser(state, login, password):
    url = "https://auth.ankama.com/login/ankama/form"
    payload = 'state=' + str(state) + '&login=' + login + '&password=' + password
    headers = {
      'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
      'Accept-Encoding': 'gzip, deflate, br, zstd',
      'Accept-Language': 'fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7',
      'Cache-Control': 'max-age=0',
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
      'Content-Type': 'application/x-www-form-urlencoded'
    }
    response = requests.post(url, headers=headers, data=payload)
    soup = BeautifulSoup(response.content, "html.parser")
    result = soup.find("redirect-uri")['uri'].replace("\"", "").partition("code=")[2]
    return result

def getApiKey(code, clientId, codeVerifier, zaapVersion):
    url = "https://auth.ankama.com/token"
    payload = "grant_type=authorization_code&code=" + str(code) + "&redirect_uri=zaap://login&client_id=" + clientId + "&code_verifier=" + str(codeVerifier)
    headers = {
      'User-Agent': "Zaap " + zaapVersion,
      'Content-Type': 'application/x-www-form-urlencoded'
    }

    response = requests.post(url, headers=headers, data=payload)
    disctJson = json.loads(response.content.decode('utf-8'))

    access_token = disctJson.get('access_token')
    refresh_token = disctJson.get('refresh_token')
    return access_token

def get_token(login:str, password:str):
    client_id = "102" # ?
    zaap_version = "3.12.12" # you can find this info on launcher's main.js
    
    code_verifier = generate_code_verifier()
    code_challenge = create_code_challenge(code_verifier)
    state = getStateFromBrowser(code_challenge, client_id)
    code = getCodeFromBrowser(state, login, password)
    api_key = getApiKey(code, client_id, code_verifier, zaap_version)

    return api_key

