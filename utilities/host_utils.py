import requests

from models.host import Host
import config


api_url = config.base_path + ":" + str(config.dsm_port) + "/rest/hosts"
headers = {'Accept': 'application/json'}

def create_host(hostTransport) -> Host:
    host = Host(hostTransport.ID, hostTransport.name, hostTransport.description, hostTransport.displayName, hostTransport.external, \
                hostTransport.externalID, hostTransport.hostGroupID, hostTransport.hostType, hostTransport.platform, \
                hostTransport.securityProfileID)
    return host


def components(host_id, sessionId, verify_ssl:bool = False):
    url = "{}/{}/components".format(api_url, host_id)
    response = requests.get(url, verify=verify_ssl, headers=headers, params={'sID': sessionId})
    return response.json()
