from suds import Client
from typing import List, Dict

import config
from utilities import cloudacct_utils as ca_utils
from utilities import iplists as ipl_utils
from utilities import portlist_utils as pl_utils
from utilities import usages_utils
from utilities.sslcontext import create_ssl_context, HTTPSTransport
from models.iplist import IPList
from models.portlist import PortList
from models.timefilter import TimeFilter
from datetime import datetime
import utilities.host_utils as hu
import utilities.timefilter_utils as tfu
import suds
from models.host import Host, HostFilter


class Manager:

    def __init__(self, username: str, password:str, tenant: str = None, verify_ssl:str = False):

        kwargs = {}
        self._username = username
        self._password = password
        self._tenant = tenant
        self.port = config.dsm_port
        self.verify_ssl = verify_ssl
        url = "{}:{}/{}".format(config.base_path, self.port, config.soap_api_wsdl)
        print(url)
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
        return ca_utils.get_cloudAccounts(self.session_id, self.verify_ssl)

    def get_cloudaccount(self, id):
        return ca_utils.get_cloudAccount(id, self.session_id, self.verify_ssl)

    def cloudaccout_testconnection(self, id: str) -> Dict[str, str]:
        return ca_utils.test_connection(id, self.session_id, self.verify_ssl)

    def cloudaccout_syncronize(self, id: str) -> Dict[str, str]:
        return ca_utils.syncronize_account(id, self.session_id, self.verify_ssl)

    def get_jvmusage(self, manager_node_id:str = "", from_date: datetime = None, to_date: datetime = None) -> Dict[str, str]:
        """
        :param manager_node_id: ID of the manager node to retrieve usage info for. If not set, usage info for all manager nodes is retrieved.
        :param from_date: The date from which to list the usage statistics. If not set, then a time of one hour ago is used.
        :param to_date: The date up to which to gather the usage. If not set, the current time is used.
        :return: Dict[str, str] containing json virtual machine statistics.
        """
        return usages_utils.jvm_usage(self.session_id, manager_node_id, from_date, to_date, self.verify_ssl)


    def get_host_by_name(self, name:str):
        response = self.client.service.hostRetrieveByName(name, sID=self.session_id)
        return hu.create_host(response)

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
        return hu.components(host_id, self.session_id)


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

    def antimalware_event_retreive(self, rangeFrom, rangeTo):
        rangeFrom = datetime(2016, 9, 23, 11, 00)
        rangeTo = datetime(2016, 9, 23, 11, 44)
        type = "CUSTOM_RANGE"
        tf = TimeFilter(rangeFrom, rangeTo, None, type)
        tft = tfu.convert_to_tansport_time_filter(tf, self.client)
        response = None

        hostFilter = HostFilter()
        hft = hostFilter.convert_to_host_filter(self.client)
        idft = self.client.factory.create('IDFilterTransport')
        idft.id = 1
        eo = self.client.factory.create('EnumOperator')
        idft.operator = eo.GREATER_THAN

        try:
            response = self.client.service.antiMalwareEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
        except Exception as e:
            fault = e['fault']

        print(response)
        return response

    def end_session(self) -> None:
        self.client.service.endSession(sID=self.session_id)

