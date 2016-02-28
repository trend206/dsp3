import collections
import re

from models.portlist import PortList

"""
def find_num_in_entry(entry):
        '''This method deals with the case when a port list has additional comment only line entries.
        these are ultimately removed from the dict'''
        if re.search(r'\d+', entry):
            return True
        else:
            return False

"""

def parse_port_lists(portlists):
    port_lists = []

    for port_list in portlists:
        items = {}
        #print(port_list.name, end="")
        if isinstance(port_list.items, collections.Iterable):
            splits = port_list.items.replace(" ", "").strip().split("\n")
            #print(splits)
            #splits = [x for x in splits if find_num_in_entry(x)]   #removes comment only entries
            splits = [x for x in splits if re.search(r'\d+', x)]   #removes comment only entries
            #print(splits)

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
