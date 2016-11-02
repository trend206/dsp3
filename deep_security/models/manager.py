from datetime import datetime
from typing import List, Dict

from suds import Client

from .host import HostFilter
from .idfilter import IDFilter
from .iplist import IPList
from .portlist import PortList
from .timefilter import TimeFilter
from ..utilities.cloudacct_utils import CloudAcctUtils
from..utilities.host_utils import HostUtils
from ..utilities import iplists as ipl_utils
from ..utilities import portlist_utils as pl_utils
from ..utilities.usages_utils import UsageUtils
from ..utilities.sslcontext import create_ssl_context, HTTPSTransport
from ..config import Config


class Manager:

    def __init__(self, username: str, password:str, tenant: str = None, \
                 hostname='app.deepsecurity.trendmicro.com', port="443", verify_ssl:str = False):
        kwargs = {}
        self._username = username
        self._password = password
        self._tenant = tenant
        self.hostname = hostname

        self.port = port
        self.verify_ssl = verify_ssl
        self.config = Config(self.hostname, self.port)
        url = self.config.soap_url()

        if verify_ssl == False:
           sslContext = create_ssl_context(False, None, None)
           kwargs['transport'] = HTTPSTransport(sslContext)

        self.client = Client(url, **kwargs)

        if tenant:
            self.session_id = self._authenticate_tenant()
        else:
            self.session_id = self.__authenticate()

    def __authenticate(self) -> str:
        return self.client.service.authenticate(username=self._username, password=self._password)


    def _authenticate_tenant(self):
        return self.client.service.authenticateTenant(tenantName=self._tenant, username=self._username, password=self._password)

    def get_api_version(self) -> str:
        return self.client.service.getApiVersion()

    def get_port_lists_all(self) -> List[PortList]:
        port_lists = self.client.service.portListRetrieveAll(sID=self.session_id)
        return pl_utils.parse_port_lists(port_lists)

    def get_ip_lists_all(self) -> List[IPList]:
        ip_lists =  self.client.service.IPListRetrieveAll(sID=self.session_id)
        return ipl_utils.parse_ip_lists(ip_lists)

    def save_ip_list(self, ip_list: IPList) -> str:
        iplto = ipl_utils.convert_to_tansport_ip_list(ip_list, self.client) #return IPListTransport object
        new_iplto = self.client.service.IPListSave(ipl=iplto, sID=self.session_id)
        if new_iplto:
            return "IP List saved successfully"
        else:
            return "There was a problem"

    def delete_ip_list(self, ids:List[str]) -> None:
        """
            Deletes the ip_list with the give id.

        Parameters
        ----------
        ids (string): The id(s) of the ip_list(s) to delete as a string.
                      For a single id use a string and a list of string ids for multiple deletions

        Returns
        -------
        nothing
        """

        self.client.service.IPListDelete(sID=self.session_id, ids=ids)


    def get_cloudaccounts(self):
        return CloudAcctUtils(self.config).get_cloudAccounts(self.session_id, self.verify_ssl)

    def get_cloudaccount(self, id):
        return CloudAcctUtils(self.config).get_cloudAccount(id, self.session_id, self.verify_ssl)

    def cloudaccout_testconnection(self, id: str) -> Dict[str, str]:
        return CloudAcctUtils(self.config).test_connection(id, self.session_id, self.verify_ssl)

    def cloudaccout_syncronize(self, id: str) -> Dict[str, str]:
        return CloudAcctUtils(self.config).syncronize_account(id, self.session_id, self.verify_ssl)

    def get_jvmusage(self, manager_node_id:str = "", from_date: datetime = None, to_date: datetime = None) -> Dict[str, str]:
        """
        :param manager_node_id: ID of the manager node to retrieve usage info for. If not set, usage info for all manager nodes is retrieved.
        :param from_date: The date from which to list the usage statistics. If not set, then a time of one hour ago is used.
        :param to_date: The date up to which to gather the usage. If not set, the current time is used.
        :return: Dict[str, str] containing json virtual machine statistics.
        """
        return UsageUtils(self.config).jvm_usage(self.session_id, manager_node_id, from_date, to_date, self.verify_ssl)


    def get_host_by_name(self, name:str):
        response = self.client.service.hostRetrieveByName(name, sID=self.session_id)
        return HostUtils(self.config).create_host(response)

    def host_status(self, id:str):
        """
        :param id: DS host id as string
        :return: suds.sudsobject.HostStatusTransport
        """
        return self.client.service.hostGetStatus(int(id), self.session_id)


    def host_agent_deactivate(self, ids:List[int]) -> None:
        self.client.service.hostAgentDeactivate(ids, self.session_id)

    def host_agent_activate(self, ids:List[int]) -> None:
        self.client.service.hostAgentActivate(ids, self.session_id)

    def host_components(self, host_id:str):
        return HostUtils(self.config).components(host_id, self.session_id)


    def host_update_now(self, ids:List[int]) -> None:
        self.client.service.hostUpdateNow(ids, self.session_id)

    def host_getevents_now(self, ids:List[int]) -> None:
        self.client.service.hostGetEventsNow(ids, self.session_id)

    def host_getevents_nowsync(self, id:str) -> None:
        self.client.service.hostGetEventsNowSync(id, self.session_id)


    def host_retrieve_by_host_group(self, host_group_id):
        return self.client.service.hostRetrieveByHostGroup(host_group_id, self.session_id)

    def host_retrieve_all(self):
        return self.client.service.hostRetrieveAll(self.session_id)



    def host_integrity_scan(self, ids:List[int]) -> None:
        self.client.service.hostIntegrityScan(ids, self.session_id)


    def dpi_rules_all(self):
        return self.client.service.DPIRuleRetrieveAll(self.session_id)

    def host_group_create(self, name):
        self.client.service.hostGroupCreate(name, self.session_id)


    def antimalware_retreive_all(self):
        return self.client.service.antiMalwareRetrieveAll(sID=self.session_id)

    def antimalware_event_retreive(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                                   host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                                   event_id=1, event_operator="GREATER_THAN"):
        """
        This function retreives antimalware (AM) events from the Deep Security Manager based on several criteria specifice
        as paramaters. Several parameters are options.


        The first set of parameters are related to the time of event retrieval. All time parameters are optional and if not set
        time_type will default to "LAST_HOUR".

        :param range_from: retrieve events from this time. if range_from and range_to are set time_type is not required.
        :param range_to: retrieve events to this time
        :param specific_time: retieve event for a specific time. if specific_time isset time_type is not required.
        :param time_type: options are: "LAST_HOUR", "LAST_24_HOURS", "LAST_7_DAYS". if set range_from, range_to, and
                          specific time are not to be specified.


        The second set of parameters are related to the host/s AM event retreival is requested for. All host parameters
        are optional and if not set host_type will default to "ALL_HOSTS".

        :param host_id: host to retrieve events for. if set host_type defaults to "SPECIFIC_HOST"
        :param host_group_id: group to retreive events for. if set host_type defaults to "HOSTS_IN_GROUP_AND_ALL_SUBGROUPS"
        :param security_profile_id: security profile to retreive events for: if set host_type defaults to "HOSTS_USING_SECURITY_PROFILE"
        :param host_type: optional. options are "ALL_HOSTS", "HOSTS_IN_GROUP", "HOSTS_USING_SECURITY_PROFILE",
                 "HOSTS_IN_GROUP_AND_ALL_SUBGROUPS","SPECIFIC_HOST", "MY_HOSTS"


        These parameters are used as a search criteria to limit the scope of objects returned by event transport object ID
        :param event_id: Event transport objects ID to filter by. if not set will default to 1
        :param event_operator: options "GREATER_THAN", "LESS_THAN", "EQUAL". if not set will default to "GREATER_THAN"

        :return: AntiMalwareEventListTransport
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.antiMalwareEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
        except Exception as e:
            fault = e['fault']

        return response


    def antimailware_retrieve_by_name(self, name):
        """
        This function retrieves the AntiMalware with the provided name (Case sensitive)

        :param name: The name of the AntiMalware to retrieve which is case sensitive
        :return: AntiMalwareTransport object.
        """
        response = self.client.service.antiMalwareRetrieveByName(name, sID=self.session_id)
        return response

    def end_session(self) -> None:
        self.client.service.endSession(sID=self.session_id)

