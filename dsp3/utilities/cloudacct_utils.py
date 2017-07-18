import json
from typing import Dict


from ..config import Config
import requests


class CloudAcctUtils:


    def __init__(self, config):
        self.config = config
        self.headers = {'Accept': 'application/json'}
        self.api_url = self.config.rest_url() + "cloudaccounts"


    def get_cloudAccounts(self, sessionID, verify_ssl=False):
        #params = {'sID': sessionID}
        cookies = dict(sID=sessionID)
        response = requests.get(self.api_url, verify=verify_ssl, headers=self.headers,cookies=cookies)
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

    def add_cloudaccount_aws(self, access_key, secret_key, sessionID, verify_ssl=False):
        url = self.api_url + '/aws'
        headers = {'Content-Type': 'application/json'}
        cookies = dict(sID=sessionID)
        data=AddAwsRequest(access_key=access_key, secret_key=secret_key).to_json()
        r = requests.post(url, data=data, verify=verify_ssl, cookies=cookies, headers=headers)
        return json.dumps(dict(status_code=r.status_code))


    def add_cloudaccount_aws_cross_account(self, external_id, role_arn, sessionID, verify_ssl=False):
        url = self.api_url + '/aws'
        headers = {'Content-Type': 'application/json'}
        cookies = dict(sID=sessionID)
        data = AddAwsRequest(external_id=external_id, role_arn=role_arn).to_json()
        r = requests.post(url, data=data, verify=verify_ssl, cookies=cookies, headers=headers)
        return json.dumps(dict(status_code=r.status_code))



class AwsCredentials:

    def __init__(self, access_key, secret_key):
        self.access_key = access_key
        self.secret_key = secret_key

    def to_json(self):
        return dict(accessKeyId=self.access_key, secretKey=self.secret_key)

class CrossAccountRole:

    def __init__(self, external_id, role_arn):
        self.external_id = external_id
        self.role_arn = role_arn


    def to_json(self):
        return dict(externalId=self.external_id, roleArn=self.role_arn)


class AddAwsRequest:

    def __init__(self, access_key=None, secret_key=None, external_id=None, role_arn=None):
        self.access_key = access_key
        self.secret_key = secret_key
        self.external_id = external_id
        self.role_arn = role_arn


    def to_json(self):
        if self.access_key is None:
            return json.dumps(dict(AddAwsAccountRequest=dict(crossAccountRole=CrossAccountRole(self.external_id, self.role_arn).to_json())))
        else:
            return json.dumps(dict(AddAwsAccountRequest=dict(awsCredentials=AwsCredentials(self.access_key, self.secret_key).to_json())))



