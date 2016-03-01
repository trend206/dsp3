from typing import Dict
import requests
import config

url = config.base_path + ":" + str(config.dsm_port) + "/"
headers = {'Accept': 'application/json'}

def getcloudAccounts(sessionID: str, verify_ssl:bool) -> Dict[str, str]:
    api_url = url + "rest/cloudaccounts"
    params = {'sID': sessionID }
    response  = requests.get(api_url, verify=verify_ssl, headers=headers, params=params)
    return response.json()