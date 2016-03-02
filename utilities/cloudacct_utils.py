from typing import Dict
import requests
import config

api_url = config.base_path + ":" + str(config.dsm_port) + "/rest/cloudaccounts"
headers = {'Accept': 'application/json'}

def get_cloudAccounts(sessionID: str, verify_ssl:bool = False) -> Dict[str, str]:
    params = {'sID': sessionID }
    response  = requests.get(api_url, verify=verify_ssl, headers=headers, params=params)
    return response.json()

def get_cloudAccount(id:str, sessionID: str, verify_ssl:bool = False) -> Dict[str, str]:
    params = {'sID': sessionID }
    url = api_url + "/{}".format(id)
    response = requests.get(url, verify=verify_ssl, headers=headers, params=params)
    return response.json()

def test_connection(id:str, sessionID:str, verify_ssl:bool = False) -> Dict[str, str]:
    params = {'sID': sessionID }
    url = api_url + "/" + id + "/testconnection"
    print(url)
    response = requests.put(url, verify=verify_ssl, headers=headers, params=params)
    print(response) #TODO on error not connected dsm api returns xml when looking for JSON
    return response.json()

def syncronize_account(id:str, sessionID:str, verify_ssl:bool = False) -> Dict[str, str]:
    params = {'sID': sessionID }
    url = api_url + "/" + id + "/synchronize"
    response = requests.put(url, verify=verify_ssl, headers=headers, params=params)
    return response.json()

