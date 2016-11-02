from typing import List

from ..models.iplist import IPList
from suds import Client


def parse_ip_lists(ip_lists) -> List[IPList]:
    """
    Used to turn a list if IPListTransport objects received by DSM into IPList objects

    :param ip_lists: IPListTransport
    :return: List[IPList]
    """
    iplists = []

    for ip_list in ip_lists:
        ips = ip_list.items.split("\n")
        ipl = IPList(ip_list.ID, ip_list.name, ip_list.description, ips)
        iplists.append(ipl)

    return iplists




def convert_to_tansport_ip_list(ip_list:IPList, suds_client:Client):
    iplt = suds_client.factory.create('IPListTransport')
    iplt.ID = ip_list.id
    iplt.description = ip_list.description
    iplt.name = ip_list.name
    iplt.items = "\n".join(item for item in ip_list.ips)
    return iplt