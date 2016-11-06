
import requests
from ..models.host import Host


class HostUtils:


    def __init__(self, config):
        self.config = config
        self.api_url = self.config.rest_url() + "hosts"
        self.headers = {'Accept': 'application/json'}


    def create_host(self, hostTransport) -> Host:
        host = Host(hostTransport.ID, hostTransport.name, hostTransport.description, hostTransport.displayName, hostTransport.external, \
                    hostTransport.externalID, hostTransport.hostGroupID, hostTransport.hostType, hostTransport.platform, \
                    hostTransport.securityProfileID)
        return host


    def components(self, host_id, sessionId, verify_ssl:bool = False):
        url = "{}/{}/components".format(self.api_url, host_id)
        response = requests.get(url, verify=verify_ssl, headers=self.headers, params={'sID': sessionId})
        return response.json()
