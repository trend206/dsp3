"""
Created on Nov 3 2016
@author: Jeff Thorne1
"""
import json
from datetime import datetime
import time
from typing import List, Dict
import urllib3

from suds import Client
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
from ..utilities.sslcontext import create_ssl_context, HTTPSTransport
from ..config import Config
from .modify_trusted_update_mode_request import ModifyTrustedUpdateModeRequest
from ..models.rest_objects import Scope, TimeRange, PropertyFilter, Scope, LiftApplicationDriftRequest, AddGlobalRulesetRulesRequest
from ..models.dpi_rule_transport import DPIRuleTransport


class Manager:

    def __init__(self, username: str, password: str, tenant=None, host: str ='app.deepsecurity.trendmicro.com',\
                 port: int = "443", verify_ssl:str = False):
        kwargs = {}
        self._username = username
        self._password = password
        self._tenant = tenant
        self.host = host
        self.headers =  {'Content-Type': 'application/json'}

        self.port = port
        self.verify_ssl = verify_ssl
        self.config = Config(self.host, self.port)
        url = self.config.soap_url()

        if verify_ssl == False:
           sslContext = create_ssl_context(False, None, None)
           kwargs['transport'] = HTTPSTransport(sslContext)
           urllib3.disable_warnings()

        self.client = Client(url, **kwargs)

        if tenant:
            self.session_id = self._authenticate_tenant()
        else:
            self.session_id = self.__authenticate()

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

    def save_ip_list(self, ip_list: IPList) -> str:
        iplto = ipl_utils.convert_to_tansport_ip_list(ip_list, self.client) #return IPListTransport object
        new_iplto = self.client.service.IPListSave(ipl=iplto, sID=self.session_id)
        if new_iplto:
            return "IP List saved successfully"
        else:
            return "There was a problem"

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
        return HostUtils(self.config).create_host(response)

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

    def host_status(self, id:str):
        """
        :param id: DS host id as string
        :return: suds.sudsobject.HostStatusTransport
        """
        return self.client.service.hostGetStatus(int(id), self.session_id)


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

    def host_group_create(self, name):
        """

        :param name:
        :return:
        """
        self.client.service.hostGroupCreate(name, self.session_id)


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


    def dpi_event_retreive(self,range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                           host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                           event_id=1, event_operator="GREATER_THAN"):
        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id,
                        type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.DPIEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id)
        except Exception as e:
            fault = e['fault']

        return response

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


    def system_event_retreive(self, range_from=None, range_to=None, specific_time=None, time_type="LAST_HOUR",
                                   host_id=None, host_group_id=None, security_profile_id=None, host_type=None,
                                   event_id=1, includeNonHostEvents=True, event_operator="GREATER_THAN"):
        """
        This function retreives System events from the Deep Security Manager based on several criteria specifice
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

        :return: SystemEventListTransport
        """

        response = None
        tft = TimeFilter(self.client, range_from, range_to, specific_time, time_type).get_transport()
        hft = HostFilter(self.client, hostGroupId=host_group_id, host_id=host_id, securityProfileId=security_profile_id, type=host_type).get_transport()
        idft = IDFilter(event_id, event_operator, self.client).get_transport()

        try:
            response = self.client.service.systemEventRetrieve(timeFilter=tft, hostFilter=hft, eventIdFilter=idft, sID=self.session_id, includeNonHostEvents=includeNonHostEvents)
        except Exception as e:
            fault = e['fault']

        return response





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
        return self.client.service.DPIRuleRetrieve(id, self.session_id)


    def security_profile_save(self, security_profile_transport_object):
        return self.client.service.securityProfileSave(sp=security_profile_transport_object, sID=self.session_id)


    def host_reccommendation_rule_ids_retrieve(self, host_id, rule_type=1, only_unassigned=False):
        """
        :param host_id:
        :param rule_type: 1=Intrusion Prevention application type rule, 2=Intrusion Prevention inspection rule, 4=Integrity Monitoring rule, 5=Log Inspection rule)
        :param only_unassigned:
        :return:
        """
        return self.client.service.hostRecommendationRuleIDsRetrieve(hostID=host_id, type=rule_type, onlyunassigned=only_unassigned, sID=self.session_id)

    def security_profile_reccommendation_rule_ids_retrieve(self, profile_id, rule_type=1):
        return self.client.service.securityProfileRecommendationRuleIDsRetrieve(securityProfileID=profile_id, type=rule_type, sID=self.session_id)



    def end_session(self) -> None:
        """
        :return:
        """
        self.client.service.endSession(sID=self.session_id)

    def is_instance_protected_by_malware(self, host_name):
        pass


    def get_security_profile(self, id: int):
        return self.client.service.securityProfileRetrieve(id, self.session_id)

    def get_security_profile_by_name(self, name):
        return self.client.service.securityProfileRetrieveByName(name=name, sID=self.session_id)


    def application_type_retreive_by_name(self, name):
        return self.client.service.applicationTypeRetrieveByName(name, self.session_id)


    def _convert_date(self, date:datetime) -> float:
        epoch = datetime.utcfromtimestamp(0)
        timestamp = (date - epoch).total_seconds() * 1000
        return int(timestamp)
