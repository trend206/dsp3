from typing import Dict


from ..config import Config
import requests


class CloudAcctUtils:


    def __init__(self, config):
        self.config = config
        self.headers = {'Accept': 'application/json'}
        self.api_url = self.config.rest_url() + "cloudaccounts"


    def get_cloudAccounts(self, sessionID, verify_ssl=False):
        print(self.api_url)
        params = {'sID': sessionID}
        print(params)
        response = requests.get(self.api_url, verify=verify_ssl, headers=self.headers, params=params)
        return response.json()


    def get_cloudAccount(self, id, sessionID, verify_ssl=False):
        params = {'sID': sessionID}
        url = self.api_url + "/{}".format(id)
        print("URL: %s" % url)
        response = requests.get(url, verify=verify_ssl, headers=self.headers, params=params)
        return response.json()


    def test_connection(self, id:str, sessionID:str, verify_ssl:bool = False) -> Dict[str, str]:
        params = {'sID': sessionID }
        url = self.api_url + "/" + id + "/testconnection"
        print(url)
        response = requests.put(url, verify=verify_ssl, headers=self.headers, params=params)
        print(response) #TODO on error not connected dsm api returns xml when looking for JSON
        return response.json()


    def syncronize_account(self, id:str, sessionID:str, verify_ssl:bool = False) -> Dict[str, str]:
        params = {'sID': sessionID }
        url = self.api_url + "/" + id + "/synchronize"
        response = requests.put(url, verify=verify_ssl, headers=self.headers, params=params)
        return response.json()

