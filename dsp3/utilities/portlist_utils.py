import collections
import re
from typing import List

from ..models.portlist import PortList


def parse_port_lists(portlists) -> List[PortList]:
    """
    Used to turn a list if PortListTransport objects received by DSM into PortList objects

    :param port_lists: PortListTransport
    :return: List[PortList]
    """
    port_lists = []

    for port_list in portlists:
        items = {}

        if isinstance(port_list.items, collections.Iterable):
            splits = port_list.items.replace(" ", "").strip().split("\n")
            splits = [x for x in splits if re.search(r'\d+', x)]   #removes comment only entries


            if len(splits) == 1 and "," in splits[0]:
                result = splits[0].split(",")
                splits = []
                for i in result:
                    splits.append(i)


            for a in splits:
                splits2 = a.split("#")

                if len(splits2) == 1:
                    items[splits2[0]] = ""
                else:
                    items[splits2[0]] = splits2[1]

        else:
            items = {}


        pl = PortList(port_list.ID, port_list.name, port_list.description, items, port_list.TBUID)
        port_lists.append(pl)


    return port_lists
