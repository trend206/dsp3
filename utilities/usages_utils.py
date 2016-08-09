from typing import Dict
import requests
import config
import urllib
from datetime import datetime

api_url = config.base_path + ":" + str(config.dsm_port) + "/rest/monitoring/usages"
headers = {'Accept': 'application/json'}

def jvm_usage(sessionID:str, manager_node_id: str, from_date: datetime, to_date: datetime, verify_ssl:bool = False) -> Dict[str, str]:
    params = {'sID': sessionID }

    if len(manager_node_id) > 0: params['managerNodeID'] = manager_node_id
    if from_date is not None: params['from']= from_date.ctime()
    if to_date is not None: params['to'] = to_date.ctime()

    url = api_url + "/jvm"
    print(params)
    response = requests.get(url, verify=verify_ssl, headers=headers, params=params)
    return response.json()