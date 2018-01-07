"""

This example was derived from a customer use case to retrieve event information
and save them as CSV files to be transformed by another process.

"""

import logging
import csv
import suds

from dsp3.models.manager import Manager

def obj_to_dictionary(field_names, obj):
    tempDict = {}
    for field in field_names:
        try:
            iterator = iter(obj[field])
        except TypeError:
            tempDict[field] = obj[field]
        else:
            if isinstance(obj[field], suds.sax.text.Text):
                tempDict[field] = obj[field]
            else:
                tempDict[field] = type(obj[field]).__name__

    return tempDict


def process_event_list(file_name, events):
    fields = events[0].__keylist__
    file = open('%s.csv' % file_name , 'w')
    with file:
        writer = csv.DictWriter(file, fieldnames=fields)
        writer.writeheader()
        for event in events:
            writer.writerow(obj_to_dictionary(fields, event))


def get_events():
    dsm = Manager(username="username", password="password", host="127.0.0.1", port="4119")

    try:
        print("Getting AM events")
        am_events = dsm.antimalware_event_retrieve(time_type="LAST_HOUR")
        print("Getting Webrep events")
        webrep_events = dsm.webrep_event_retrieve(time_type="LAST_7_DAYS")
        print("Getting FW events")
        fw_events = dsm.fw_event_retrieve(time_type="LAST_7_DAYS")
        print("Getting DPI events")
        dpi_events = dsm.dpi_event_retrieve(time_type="LAST_7_DAYS")
        print("Getting IM events")
        im_events = dsm.im_event_retrieve(time_type="LAST_7_DAYS")
        print("Getting LI events")
        li_events = dsm.li_event_retrieve(time_type="LAST_7_DAYS")
        print("Getting System events")
        system_events = dsm.system_event_retrieve(time_type="LAST_7_DAYS")

        event_list = {'am_events': am_events, 'webrep_events': webrep_events, 'fw_events': fw_events, 'dpi_events': dpi_events,
                      'im_events': im_events, 'li_events': li_events, 'system_events': system_events}

        for file_name, events in event_list.items():
            process_event_list(file_name, events)

    except Exception as e:
        logging.error(e, exc_info=True)
    finally:
        dsm.end_session()


if __name__ == "__main__":
    get_events()