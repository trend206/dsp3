"""
Created on Nov 3 2016
@author: Jeff Thorne
"""
import json
from datetime import datetime
import time
from typing import List, Dict
import urllib3
import ssl
import sys
import logging

from suds import Client, WebFault
import requests

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
from ..utilities.sslcontext import create_ssl_context, get_https_transport
from ..config import Config
from .modify_trusted_update_mode_request import ModifyTrustedUpdateModeRequest
from ..models.rest_objects import Scope, TimeRange, PropertyFilter, Scope, LiftApplicationDriftRequest, AddGlobalRulesetRulesRequest
from ..models.dpi_rule_transport import DPIRuleTransport




class Manager:

    def __init__(self, api_key: str = None, username: str = None, password: str = None, tenant=None, host: str ='app.deepsecurity.trendmicro.com',\
                 port: int = "443", verify_ssl:bool = False, cacert_file:str = False, api_version='v1'):
        """
        :param api_key   require to use some new rest calls. This calls will indicate api_key auth required in doc.
        :param username: required to use deprecated SOAP and rest calls
        :param password: required to use deprecated SOAP and rest calls
        :param tenant:   required to use deprecated SOAP and rest calls
        :param host:
        :param port:
        :param verify_ssl:
        :param cacert_file: optional CA certificates to trust for certificate verification
        """
        kwargs = {}

        self.api_version = api_version
        self.headers = {'Content-Type': 'application/json', 'api-version': self.api_version}

        if api_key is not None:
            self.api_key = api_key
            self.headers['api-secret-key'] = self.api_key

        self._username = username
        self._password = password
        self._tenant = tenant
        self.host = host
        self.port = port
        self.verify_ssl = verify_ssl
        self.config = Config(self.host, self.port)
        url = self.config.soap_url()
        urllib3.disable_warnings()

        kwargs['transport'] = get_https_transport(verify_ssl, cacert_file)

        try:
            self.client = Client(url, **kwargs)
        except ssl.CertificateError as ce:
            print(ce)
            sys.exit("could not verify ssl cert")

        try:
            if tenant and username is not None:
                self.session_id = self._authenticate_tenant()
            elif username is not None:
                self.session_id = self.__authenticate()
        except WebFault as detail:
            print("Authentication error: ", detail)
            sys.exit()

    def __authenticate(self) -> str:
        return self.client.service.authenticate(username=self._username, password=self._password)

    def authenticate_via_rest(self):
        dscrendentials = json.dumps(dict(dsCredentials=dict(userName=self._username, password=self._password)))
        url = "https://{}:{}/rest/authentication/login".format(self.host, self.port)
        headers = {'Content-Type': 'application/json'}
        r = requests.post(url, data=dscrendentials, verify=False, headers=headers)
        return r.content.decode('utf-8')

    def _authenticate_tenant(self):
        return self.client.service.authenticateTenant(tenantName=self._tenant, username=self._username, password=self._password)

    def get_api_version(self) -> int:
        """
        Retrieves the api version of Trend Micro's Deep Security SOAP Web Service.

        :return: int: The api version number.
        """
        return self.client.service.getApiVersion()

    def get_port_lists_all(self) -> List[PortList]:
        """
        Retrieves a list of all reusable post lists.

        :return: List[dsp3.models.portlist.PortList]
        """
        port_lists = self.client.service.portListRetrieveAll(sID=self.session_id)
        return pl_utils.parse_port_lists(port_lists)

    def get_ip_lists_all(self) -> List[IPList]:
        ip_lists =  self.client.service.IPListRetrieveAll(sID=self.session_id)
        return ipl_utils.parse_ip_lists(ip_lists)

    def save_ip_list(self, ip_list: IPList) -> Dict:
        iplto = ipl_utils.convert_to_tansport_ip_list(ip_list, self.client) #return IPListTransport object
        new_iplto = self.client.service.IPListSave(ipl=iplto, sID=self.session_id)
        if new_iplto:
            return new_iplto
        else:
            return "There was a problem"

    def ip_list_save(self,ip_list):
        return self.client.service.IPListSave(ipl=ip_list, sID=self.session_id)

    def get_ip_list(self, id):
        return self.client.service.IPListRetrieve(id, self.session_id)

    def get_ip_list_by_name(self, name):
        return self.client.service.IPListRetrieveByName(name, self.session_id)


    def delete_ip_list(self, ids):
        """
          Deletes the ip_list with the give id

          :param ids: The id(s) of the ip_list(s) to delete as a string.\
                      For a single id use a string and a list of string ids for multiple deletions
          :return: None
        """

        self.client.service.IPListDelete(sID=self.session_id, ids=ids)


    def get_cloudaccounts(self):
        """

        :return:
        """
        return CloudAcctUtils(self.config).get_cloudAccounts(self.session_id, self.verify_ssl)

    def get_cloudaccount(self, id):
        """

        :param id:
        :return:
        """
        return CloudAcctUtils(self.config).get_cloudAccount(id, self.session_id, self.verify_ssl)

    def cloudaccout_testconnection(self, id: str) -> Dict[str, str]:
        """

        :param id:
        :return:
        """
        return CloudAcctUtils(self.config).test_connection(id, self.session_id, self.verify_ssl)

    def cloudaccout_syncronize(self, id: str) -> Dict[str, str]:
        """

        :param id:
        :return:
        """
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
        """
        :param name:
        :return:
        """
        response = self.client.service.hostRetrieveByName(name, sID=self.session_id)
        if response == None:
            return None
        else:
            return HostUtils(self.config).create_host(response)

    def host_create(self, host_transport):
        return self.client.service.hostCreate(host=host_transport, sId=self.session_id)

    def host_detail_retrieve(self, host_group_id: int=None, host_id:int = None, security_profile_id:int = None,
                             host_type=None, host_detail_level: str ='HIGH'):
        """
        This function allows it, to get more information about hosts.
        (e.g. 'virtual Name' and 'virtual Uuid' of host)

        :param host_detail_level: options are: "LOW", "MEDIUM" and "HIGH"
        """

        host_filter = HostFilter(
            self.client, hostGroupId=host_group_id, host_id=host_id,
            securityProfileId=security_profile_id, type=host_type
        ).get_transport()

        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id,
                         type=host_type).get_transport()


        response = self.client.service.hostDetailRetrieve(hostFilter=host_filter, hostDetailLevel=host_detail_level, sID=self.session_id)

        if isinstance(response, list) and len(response) == 1:
            return response[0]
        return response

    def host_status(self, id:int):
        """
        :param id: DS host id as string
        :return: suds.sudsobject.HostStatusTransport
        """
        return self.client.service.hostGetStatus(id, self.session_id)

    def host_move_to_hosts_group(self, host_ids, host_group_id):
        return self.client.service.hostMoveToHostGroup(host_ids, host_group_id, self.session_id)

    def host_agent_deactivate(self, ids:List[int]) -> None:
        """

        :param ids:
        :return:
        """
        self.client.service.hostAgentDeactivate(ids, self.session_id)



    def host_agent_activate(self, ids:List[int]) -> None:
        """

        :param ids:
        :return:
        """
        self.client.service.hostAgentActivate(ids, self.session_id)

    def host_components(self, host_id:str):
        """

        :param host_id:
        :return:
        """
        return HostUtils(self.config).components(host_id, self.session_id)


    def host_update_now(self, ids:List[int]) -> None:
        """

        :param ids:
        :return:
        """
        self.client.service.hostUpdateNow(ids, self.session_id)

    def host_getevents_now(self, ids:List[int]) -> None:
        """

        :param ids:
        :return:
        """
        self.client.service.hostGetEventsNow(ids, self.session_id)

    def host_getevents_nowsync(self, id:str) -> None:
        """

        :param id:
        :return:
        """
        self.client.service.hostGetEventsNowSync(id, self.session_id)


    def host_retrieve_by_hostgroup(self, host_group_id):
        """
        Retrieve hosts by host group.

        :param host_group_id: id of the host group.
        :return: List of HostTransport Objects. Example below:

                    (HostTransport){
                           ID = 1604
                           description = None
                           name = "ec2-184-72-238-128.compute-1.amazonaws.com"
                           displayName = "Ubuntu nginx Web Server"
                           external = True
                           externalID = None
                           hostGroupID = 432
                           hostType = "STANDARD"
                           platform = "Ubuntu Linux 12 (64 bit) (3.2.0-31-virtual)"
                           securityProfileID = 201
                    }
        """
        return self.client.service.hostRetrieveByHostGroup(host_group_id, self.session_id)

    def host_retrieve_all(self):
        """

        :return:
        """
        return self.client.service.hostRetrieveAll(self.session_id)


    def host_group_retrieve_all(self):
        """

        :return: List of HostGroupTransport objects. Example object below:
                        (HostGroupTransport){
                                                ID = 425
                                                description = None
                                                name = "vpc-7b3bd512"
                                                external = True
                                                externalID = None
                                                parentGroupID = 424
                                             }
        """
        return self.client.service.hostGroupRetrieveAll(self.session_id)



    def host_integrity_scan(self, ids:List[int]) -> None:
        """

        :param ids:
        :return:
        """
        self.client.service.hostIntegrityScan(ids, self.session_id)


    def dpi_rules_all(self):
        """

        :return:
        """
        return self.client.service.DPIRuleRetrieveAll(self.session_id)

    def host_group_retrieve_by_name(self, name):
        return self.client.service.hostGroupRetrieveByName(name, self.session_id)

    def host_group_delete(self, id):
        return self.client.service.hostGroupDelete(id, self.session_id)

    def host_group_retrieve_by_id(self, id):
        return self.client.service.hostGroupRetrieve(id, self.session_id)


    def host_group_create(self, name, description="", external=False, external_id=None, parent_group_id=None):
        """

        :param name:
        :return:
        """
        hgt = self.client.factory.create('HostGroupTransport')
        hgt['name'] = name
        hgt['description'] = description
        hgt['external'] = external
        hgt['externalID'] = external_id
        hgt['parentGroupID'] = parent_group_id
        return self.client.service.hostGroupCreate(hgt, self.session_id)


    def hostRetrieveByHostGroup(self, id):
        return self.client.service.hostRetrieveByHostGroup(id, self.session_id)


    def host_recommendation_scan(self, ids:List[int]):
        """
        This function runs a recomendation scan on an individual or list of hosts by id.

        :param ids: list of host ids to scan for reccomendations
        :return: None
        """
        response = self.client.service.hostRecommendationScan(ids, self.session_id)
        return response


    def antimalware_retreive_all(self):
        """

        :return:
        """
        return self.client.service.antiMalwareRetrieveAll(sID=self.session_id)



    def antimalware_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
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

        :return: None or [] of AntiMalwareEvent
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.antiMalwareEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
            if response['antiMalwareEvents'] is None:
                return None

            return response['antiMalwareEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)


    def webrep_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                                   host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                                   event_id=1, event_operator="GREATER_THAN"):
        """
        This function retreives web reputation (WR) events from the Deep Security Manager based on several criteria specifice
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

        :return: None or [] of WebReputationEvent
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.webReputationEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
            if response['webReputationEvents'] is None:
                return None


            return response['webReputationEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)


    def fw_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                                   host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                                   event_id=1, event_operator="GREATER_THAN"):
        """
        This function retrieves firewall (FW) events from the Deep Security Manager based on several criteria specifice
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

        :return: None or [] of FireWallEvent
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.firewallEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
            if response['firewallEvents'] is None:
                return None

            return response['firewallEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)


    def dpi_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                                   host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                                   event_id=1, event_operator="GREATER_THAN"):
        """
        This function retrieves Deep Packet Inspection (DPI) events from the Deep Security Manager based on several criteria specifice
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

        :return: None or [] of DPIEventTransport
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.DPIEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
            if response['DPIEvents'] is None:
                return None

            return response['DPIEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)

    def im_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                                   host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                                   event_id=1, event_operator="GREATER_THAN"):
        """
        This function retrieves integrity monitorinig (IM) events from the Deep Security Manager based on several criteria specifice
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

        :return: None or [] of IntegrityEventTransport
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.integrityEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
            if response['integrityEvents'] is None:
                return None

            return response['integrityEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)


    def li_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                          host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                          event_id=1, event_operator="GREATER_THAN"):
        """
        This function retrieves log inspection (LI) events from the Deep Security Manager based on several criteria specifice
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

        :return: None or [] of LogInspectionEventTransport
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id,
                         type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.logInspectionEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft,
                                                                  sID=self.session_id)

            if response['logInspectionEvents'] is None:
                return None

            return response['logInspectionEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)




    def antimailware_retrieve_by_name(self, name):
        """
        This function retrieves the AntiMalware with the provided name (Case sensitive)

        :param name: The name of the AntiMalware to retrieve which is case sensitive
        :return: AntiMalwareTransport object.
        """
        response = self.client.service.antiMalwareRetrieveByName(name, sID=self.session_id)
        return response


    def system_event_retrieve(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                              host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                              event_id=1, event_operator="GREATER_THAN", includeNonHostEvents=True):
        """
               This function retrieves system events from the Deep Security Manager based on several criteria specifice
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

               :return: None or [] of SystemEventTransport
         """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id,
                         type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.systemEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft,
                                                               sID=self.session_id, includeNonHostEvents=includeNonHostEvents)


            if response['systemEvents'] is None:
                return None

            return response['systemEvents']['item']

        except TypeError as te:
            logging.error(te, exc_info=True)
        except Exception as e:
            logging.error(e, exc_info=True)

    def set_trusted_update_mode(self, host_id: int, duration:int = 0, enabled: bool = True) -> str:
        """
        This function sets the trusted (maintenance) mode status of the host specified for a specific duration.
        NOTE: This call only supported in DS10 and higher

        :param host_id: host to enable or disable trusted (maintenance) mode for
        :param duration: the amount of time to enable trusted mode. Not required for disable request
        :param enabled: True to enable or False to disable trusted mode
        :return: status code
        """
        modify_trusted_updatemode_request = ModifyTrustedUpdateModeRequest(duration, enabled)
        url = "https://{}:{}/rest/hosts/{}/trusted-update-mode".format(self.host, self.port, host_id)
        headers = {'Content-Type': 'application/json'}
        cookies = dict(sID=self.session_id)
        r = requests.post(url, data=modify_trusted_updatemode_request.to_json(), verify=self.verify_ssl, cookies=cookies, headers=headers)
        return json.dumps(dict(status_code=r.status_code))

    def get_trusted_update_mode(self, host_id: int) -> str:
        """
        This function retreives the trusted (maintenance) mode status of the host specified.
        NOTE: This call only supported in DS10 and higher

        :param host_id: the id of the host to retreive trust update mode (maintenance) status on
        :return: json string of the format
                {  "DescribeTrustedUpdateModeResponse":
                    {
                      "startTimeHuman":"Sunday Jan 29 18:00:17 PM EST",
                      "endTimeHuman":"Sunday Jan 29 18:10:17 PM EST",
                      "state":"on",
                      "startTime":1485730817728,
                      "endTime":1485731417728
                   }
                }
        """
        url = "https://{}:{}/rest/hosts/{}/trusted-update-mode".format(self.host, self.port, host_id)
        headers = {'Content-Type': 'application/json'}
        cookies = dict(sID=self.session_id)
        r = requests.get(url, verify=self.verify_ssl, cookies=cookies, headers=headers)
        response = json.loads(r.content.decode('utf-8'))
        state = response['DescribeTrustedUpdateModeResponse']['state']

        if state != "off":
            start_time = response['DescribeTrustedUpdateModeResponse']['startTime']
            end_time = response['DescribeTrustedUpdateModeResponse']['endTime']
            human_start_time = time.strftime("%A %b %d %-H:%M:%S %p %Z", time.localtime(start_time / 1000.0)) if start_time != None else None
            human_end_time = time.strftime("%A %b %d %-H:%M:%S %p %Z", time.localtime(end_time / 1000.0)) if end_time != None else None

            return json.dumps(dict(DescribeTrustedUpdateModeResponse=dict(startTime=start_time, endTime=end_time, state=state, \
                                                                      endTimeHuman=human_end_time, startTimeHuman=human_start_time )))
        else:
            return json.dumps(dict(DescribeTrustedUpdateModeResponse=dict(state=state)))

    def decision_logs(self) -> Dict[str, str]:
        url = "https://{}:{}/rest/decision-logs".format(self.host, self.port)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return r.content.decode('utf-8')

    def decision_log(self, decision_log_id:int) -> Dict[str, str]:
        url = "https://{}:{}/rest/decision-logs/{}".format(self.host, self.port, decision_log_id)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return r.content.decode('utf-8')

    def decision_log_details(self, decision_log_id:int, start_id:int = 1, count:int = 1) -> Dict[str, str]:
        params = {'startID': start_id, 'count': count}
        url = "https://{}:{}/rest/decision-logs/{}/details".format(self.host, self.port, decision_log_id)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return r.content.decode('utf-8')



    def appcontrol_events(self, event_time: datetime = None, event_time_op:str = None, max_items: int = None) -> Dict[str, str]:
        """
        TODO: IMplement eventID and eventIDOp parameters
        NOTE: This call only supported in DS10 and higher

        :param event_time:  the event time to query for events.
        :param event_time_op: gt(greater than), ge(greater than or equal to), eq(eqaul to), lt(less than), and le(less than or equal to).
                              If an unsupported operator is provided, the default is 'eq'.
        :param max_items:  the maximum number of events to return
        :return: ListEventsResponse json dictionary
        """
        url = "https://{}:{}/rest/events/appcontrol".format(self.host, self.port)
        params = {'eventTime': event_time, 'eventTimeOp':event_time_op, 'maxItems': max_items }
        params['eventTime'] = self._convert_date(event_time) if event_time != None else None   #convert event_time to ms since epoch timestamp
        params = dict((k,v) for k,v in params.items() if v is not None)
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))

    """ Seems to have been removed from API
    def license_info(self, module):
        url = "https://{}:{}/rest/license/listLicenseInfo".format(self.host, self.port)
        params = {'module': module, 'sID': self.session_id}
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))

    """

    def manager_info_version(self) -> str:
        """
        Retrieve DSM version.

        :return: str representation of DSM version
        """
        url = "https://{}:{}/rest/managerInfo/version".format(self.host, self.port)
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return r.content.decode('utf-8')

    def manager_info_status_summary(self) -> dict:
        """
        Retrieves the status summary of the system

        :return: StatusSummaryElement
        """
        url = "https://{}:{}/rest/managerInfo/statusSummary".format(self.host, self.port)
        params = {'sID': self.session_id}
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))

    def manager_info_components(self) -> dict:
        """
        Retrieves detailed component info in current system

        :return: ComponentInfoElement
        """
        url = "https://{}:{}/rest/managerInfo/components".format(self.host, self.port)
        params = {'sID': self.session_id}
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))

    def manager_info_feature_summary(self, timescale: int) -> dict:
        """
        Retrieves the status summary of each protection feature

        :param timescale 1 [last 7 days] or 2 [last 24 hours]
        :return: FeatureSummaryElement
        """
        url = "https://{}:{}/rest/managerInfo/featureSummary".format(self.host, self.port)
        params = {'sID': self.session_id, 'timescale': timescale}
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))


    def alerts(self, alert_id:int=None, dismissed:bool=None, maxItems:int=None, op:str=None) -> dict:
        """
        alerts retrieves alert information from the dsm

        :param alert_id:  (optional) used to define the starting point for the query. Combine with op to page through results.
        :param dismissed: (optional) include alerts that have been dismissed.
        :param maxItems:  (optional) the number of items to retrieve.
        :param op:        (optional, required if alertID is specified) Currently supported operations are: gt, ge, eq, lt,le

        :return:   ListAlertsResponse
        """
        url = "https://{}:{}/rest/alerts".format(self.host, self.port)
        params = {'alertID': alert_id, 'dismised': dismissed, 'maxItems': maxItems, 'op':op}
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))

    def appcontrol_event(self, event_id:int) -> Dict[str, str]:
        """
        Get the Application Control event with the specified event ID.

        :param event_id: the event ID
        :return: DescribeEventResponse json dict. containing the event with the specific ID
        """
        url = "https://{}:{}/rest/events/appcontrol/{}".format(self.host, self.port, event_id)
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return json.loads(r.content.decode('utf-8'))

    def drift_applications(self, host_id:int, start_time: datetime, end_time:datetime, file_name:str, host_name:str):
        time_range = TimeRange(end_time, start_time)
        property_filter = PropertyFilter(file_name, host_name)
        scope = Scope(property_filter, time_range)
        lar = LiftApplicationDriftRequest(scope)
        url = "https://{}:{}/rest/software-inventory/drift/applications".format(self.host, self.port)
        r = requests.post(url, data=lar.to_json(), verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return json.loads(r.content.decode('utf-8'))



    def list_block_by_hash_rules(self):
        """
        NOTE: This call only works with DSM's > 10.2

        :return: Listing of existing Block by Hash Rules from Global Ruleset

        """
        url = "https://{}:{}/rest/rulesets/global".format(self.host, self.port)
        r = requests.get(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return json.loads(r.content)

    def add_block_by_hash_rule(self, hash, description):
        """
        NOTE: This call only works with DSM's > 10.2
        This methods allows for the Adding of a new Block by Hash Rules to Global Ruleset.

        :param hash: the sha256 hash of the file to bock
        :param description: description of new BLock by Hash Rule
        :return: rule that was successfully added along with its corresponding ruleID
        """
        url = "https://{}:{}/rest/rulesets/global/rules".format(self.host, self.port)
        rule_request = AddGlobalRulesetRulesRequest(hash, description)
        r = requests.post(url, data=rule_request.to_json(), verify=self.verify_ssl, cookies=dict(sID=self.session_id),headers=self.headers)
        return json.loads(r.content)

    def delete_block_by_hash_rule(self, rule_id):
        """
        NOTE: This call only works with DSM's > 10.2
        This method provides for deleting an existing Block by Hash Rules to Global Ruleset.

        :param rule_id: The id of the Block by Hash rule to delete
        :return: response payload
        """
        url = "https://{}:{}/rest/rulesets/global/rules/{}".format(self.host, self.port, rule_id)
        r = requests.delete(url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return r



    def add_aws_cloud_account_with_keys(self, access_key, secret_key):
        return CloudAcctUtils(self.config).add_cloudaccount_aws(access_key, secret_key, self.session_id)

    def add_aws_cloud_account_with_cross_account_role(self, external_id, role_arn):
        return CloudAcctUtils(self.config).add_cloudaccount_aws_cross_account(external_id, role_arn, self.session_id)

    def security_profile_assign_to_host(self, securityid: int, hostid: int) -> None:
        """
        :param securityid: security policy id
        :param hostid: host id
        :return:
        """
        self.client.service.securityProfileAssignToHost(securityid, hostid, self.session_id)

    def host_delete(self, ids):
        return self.client.service.hostDelete(ids, self.session_id)

    def dpi_rule_save(self, application_type, name, eventOnPacketDrop, eventOnPacketModify, templateType, patternAction,
                patternIf, priority, signatureAction, severity, ruleXML, detectOnly=False, disableEvent=False,
                 ignoreRecommendations=False, includePacketData=False, patternCaseSensitive=False, raiseAlert=False,
                 signatureCaseSensitive=False, cvssScore=0, authoritative=False):

        rule = self.dpi_rule_retrieve_by_name(name)
        rule_id = None
        app_id = self.application_type_retreive_by_name(application_type).ID

        if rule and rule.ID is not None:
            rule_id = rule.ID
            #return '{"response": "A rule with that name already exists"}'


        dpirt = DPIRuleTransport(self.client, name, app_id, eventOnPacketDrop, eventOnPacketModify, templateType, patternAction,
                patternIf, priority, signatureAction, severity, ruleXML, rule_id, detectOnly, disableEvent,
                 ignoreRecommendations, includePacketData, patternCaseSensitive, raiseAlert,
                 signatureCaseSensitive, cvssScore, authoritative)

        return self.client.service.DPIRuleSave(ipsf=dpirt.get_transport(), sID=self.session_id)


    def dpi_rule_retrieve_by_name(self, name):
        return self.client.service.DPIRuleRetrieveByName(name, self.session_id)

    def dpi_rule_retrieve_by_id(self, id):
        """
        Retrieves info on a DPI rule by rule id

        :param id: dpi rule id
        :return: suds.sudsobject.DPIRuleTransport
        """
        return self.client.service.DPIRuleRetrieve(id, self.session_id)


    def fw_rule_retrieve_by_id(self, id):
        """
        Retrieves info on a FW rule by rule id

        :param id: fw rule id
        :return: suds.sudsobject.FirewallRuleTransport
        """
        return self.client.service.firewallRuleRetrieve(id, self.session_id)


    def fw_rule_save(self, fw_rule):
        """

        :param fw_rule: FirewallRuleTransport object to create or save
        :return: Newly created FirewallRuleTransport object.
        """
        return self.client.service.firewallRuleSave(fw_rule, self.session_id)


    def security_profile_save(self, security_profile_transport_object):
        """
        :param security_profile_transport_object: suds.sudsobject.SecurityProfileTransport
        :return: suds.sudsobject.SecurityProfileTransport
        """
        return self.client.service.securityProfileSave(sp=security_profile_transport_object, sID=self.session_id)


    def host_reccommendation_rule_ids_retrieve(self, host_id, rule_type=1, only_unassigned=False):
        """
        :param host_id:
        :param rule_type: 1=Intrusion Prevention application type rule, 2=Intrusion Prevention inspection rule, 4=Integrity Monitoring rule, 5=Log Inspection rule)
        :param only_unassigned:
        :return: list of rule ids
        """
        return self.client.service.hostRecommendationRuleIDsRetrieve(hostID=host_id, type=rule_type, onlyunassigned=only_unassigned, sID=self.session_id)

    def security_profile_reccommendation_rule_ids_retrieve(self, profile_id, rule_type=1):
        """
        :param profile_id: security policy id
        :param rule_type: rule_type: 1=Intrusion Prevention application type rule, 2=Intrusion Prevention inspection rule, 4=Integrity Monitoring rule, 5=Log Inspection rule
        :return: list of rule ids
        """
        return self.client.service.securityProfileRecommendationRuleIDsRetrieve(securityProfileID=profile_id, type=rule_type, sID=self.session_id)



    def end_session(self) -> None:
        """
        :return:
        """
        self.client.service.endSession(sID=self.session_id)

    def is_instance_protected_by_malware(self, host_name):
        pass


    def get_security_profile(self, id: int):
        """
        :param id: security policy id
        :return: suds.sudsobject.SecurityProfileTransport
        """
        return self.client.service.securityProfileRetrieve(id, self.session_id)

    def get_security_profile_by_name(self, name):
        """
        :param name: security policy name
        :return: suds.sudsobject.SecurityProfileTransport
        """
        return self.client.service.securityProfileRetrieveByName(name=name, sID=self.session_id)


    def host_clear_warnings_and_errors(self, hosts):
        """

        :param hosts: int if single host or list[int] if many hosts
        :return:
        """
        return self.client.service.hostClearWarningsErrors(hostIDs=hosts, sID=self.session_id)

    def application_type_retreive_by_name(self, name):
        return self.client.service.applicationTypeRetrieveByName(name, self.session_id)

    def software_retrieve_all(self):
        return self.client.service.softwareRetrieveAll(self.session_id)

    def administrators(self, admin_id:int=None, admin_op:str=None, max_items:int=None) -> Dict[str, str]:
        """
        administrators lists administrators.

        :param admin_id used to define the starting point for the query. Combine with administratorIDOp.
        :params admin_op required if administratorID is specified. gt, ge, eq, lt,le
        :return: ListAdministratorsResponse json
        """
        params = {'administratorID':admin_id, 'administratorIDOp': admin_op, 'maxItems': max_items}
        url = "https://{}:{}/rest/administrators".format(self.host, self.port)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers, params=params)
        return json.loads(r.content.decode('utf-8'))


    def event_based(self) -> dict:
        """
        List event-based tasks.

        :return: ListEventBasedTasksResponse json object
        """
        url = "https://{}:{}/rest/tasks/event-based".format(self.host, self.port)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return json.loads(r.content.decode('utf-8'))


    def event_based_delete(self, id:int) -> int:
        """
        Delete an event-based task.

        :param id: id of event based task
        :return: http status code
        """
        url = "https://{}:{}/rest/tasks/event-based/{}".format(self.host, self.port, id)
        r = requests.delete(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), headers=self.headers)
        return r.status_code

    def event_based_task_create(self, name:str, conditions:List[dict], actions:List[dict], task_type:str='computer-created-by-system',
                                enabled:bool=True) -> dict:
        """

        :param name:
        :param conditions list of dicts {field:'', key:'', value:''}
               field value one of: hostnameMatch, vcenterMatch, cloudProviderMatch, securityGroupMatch, imageIdMatch,
               esxMatch,folderMatch,platformMatch, applianceProtectionAvailable True or False,
               applianceProtectionActivated True or False, lastUsedIP, tagMatch, nsxSecurityGroupMatch
        :param actions List of dicts {'type':'', 'parameterValue':''}
               type value one of: activate, assign-policy, assign-relay, assign-group, deactivate
        :param type: one of: computer-created-by-system, agent-initiated-activation, agent-ip-changed, nsx-protection-changed,
                     computer-powered-on-by-system
        :param enabled the enabled state for this task.

        :return: CreateEventBasedTaskResponse
        """
        event_task = dict(name=name, type=task_type, enabled=enabled, conditions=conditions, actions=actions)
        task_request = dict(CreateEventBasedTaskRequest=dict(task=event_task))
        json_task = json.dumps(task_request)
        url = "https://{}:{}/rest/tasks/event-based".format(self.host, self.port)
        headers = {'Content-Type': 'application/json'}
        r = requests.post(url, data=json_task, verify=False, cookies=dict(sID=self.session_id), headers=headers)
        return r.content.decode('utf-8')



    def _convert_date(self, date:datetime) -> float:
        epoch = datetime.utcfromtimestamp(0)
        timestamp = (date - epoch).total_seconds() * 1000
        return int(timestamp)



    def list_relays(self, ascending:bool=None, background:bool=False, failed:bool=False, max_items:int=None, offset:int=None,
                    sort_by:str=None):
        """
        List relays
        :param ascending:  (optional) set true indicate ascending. Default is true. This parameter only works with sortBy.
        :param background: (optional) If true, does not extends the session. Default false.
        :param failed: (optional) set true, indicate that the API only returns the failure records of enabling/disabling.
                        If false, the API returns valid relays according to the specified criteria. Default is false.
        :param maxItems: (optional) the number of items to retrieve. The maximum value for this parameter is controlled
                         by the "Maximum number of items to retrieve from database" setting on the administrator account,
                         which defaults to 5000.
        :param offset: (optional) used to define the starting point for the query. This parameter only works with sortBy.
        :param sort_by: (optional) used to define the sorting field. The only available sorting column is Name. However,
                        if sortBy is not specified, the default sorting column is id. This parameter can work with maxItems,
                        ascending and offset.
        :return: ListRelaysResponse a ListRelaysResponse with the host details.
        """
        url = "https://{}:{}/rest/relays".format(self.host, self.port)
        params = dict(ascending=ascending, background=background, failed=failed, maxItems=max_items, offset=offset, sortBy=sort_by)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), params=params, headers=self.headers)
        return json.dumps(r.content.decode('utf-8'))



    def scripts(self, id:int=None, max_items:int=None, op:str=None):
        """

        :param id: (optional) used to define the starting point for the query. Combine with op to page through results.
        :param max_integers:

        :param op: (optional, required if id is specified) Currently supported operations are:
                    gt (greater than), ge (greater than or equal to), eq (equal to), lt (less than),
                    le (less than or equal to)
        :return: ListScriptsResponse with the list of scripts.

        """
        url = "https://{}:{}/rest/scripts".format(self.host, self.port)
        params = dict(id=id, maxItems=max_items, op=op)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), params=params,
                         headers=self.headers)
        return json.dumps(r.content.decode('utf-8'))


    def reports(self, id:int=None, max_items:int=None, op:str=None):
        """
        List report templates.
          :param id: (optional) used to define the starting point for the query. Combine with op to page through results.
          :param max_integers:

          :param op: (optional, required if id is specified) Currently supported operations are:
                      gt (greater than), ge (greater than or equal to), eq (equal to), lt (less than),
                      le (less than or equal to)
          :return: ListReportTemplatesResponse with the report template details.

          """
        url = "https://{}:{}/rest/reports".format(self.host, self.port)
        params = dict(id=id, maxItems=max_items, op=op)
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id), params=params,
                         headers=self.headers)
        return json.dumps(r.content.decode('utf-8'))


    def computer_describe(self, host_id:int):
        url = "https://{}:{}/api/computers/{}".format(self.host, self.port, host_id)
        self.headers['api-version'] = 'v11.2.88'
        r = requests.get(url=url, verify=self.verify_ssl, cookies=dict(sID=self.session_id),headers=self.headers)
        return json.dumps(r.content.decode('utf-8'))


    def api_keys(self):
        '''
        api_key auth required to use this call

        :return: json object listing all api key info
        '''
        url = "https://{}:{}/api/apikeys".format(self.host, self.port)
        r = requests.get(url=url, verify=self.verify_ssl, headers=self.headers)
        return json.loads(r.content.decode('utf-8'))


