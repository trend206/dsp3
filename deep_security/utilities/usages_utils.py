from datetime import datetime
from typing import Dict
import requests


from ..config import Config



class UsageUtils:


    def __init__(self, config):
        self.config = config
        self.api_url = self.config.rest_url() + "monitoring/usages"
        self.headers = {'Accept': 'application/json'}

    def jvm_usage(self, sessionID:str, manager_node_id: str, from_date: datetime, to_date: datetime, verify_ssl:bool = False) -> Dict[str, str]:
        params = {'sID': sessionID }

        if len(manager_node_id) > 0: params['managerNodeID'] = manager_node_id
        if from_date is not None: params['from']= from_date.ctime()
        if to_date is not None: params['to'] = to_date.ctime()

        url = self.api_url + "/jvm"
        print(params)
        response = requests.get(url, verify=verify_ssl, headers=self.headers, params=params)
        return response.json()