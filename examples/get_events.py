from datetime import datetime, timedelta
from dsp3.models.manager import Manager


dsm = Manager(username="username", password="password", host="127.0.0.1", port="4119")

#Example 1: Get antimalware events for all hosts in the last hour
# time_type options: "LAST_HOUR", "LAST_24_HOURS", "LAST_7_DAYS", "CUSTOM_RANGE"
am_events = dsm.antimalware_event_retrieve(time_type="LAST_HOUR")


#Example 2: Get fw events for all hosts during a specific time
date_to = datetime.now()
date_from = date_to - timedelta(hours=3)
fw_events = dsm.fw_event_retrieve(range_from=date_from, range_to=date_to, time_type="CUSTOM_RANGE")


#Example 3: Get web reputation events for a specific host in the last 24 hours
wr_events = dsm.webrep_event_retrieve(time_type="LAST_24_HOURS", host_id=11, host_type="SPECIFIC_HOST")


#Example 4: Retrieve DPI Events by Host Group
dpi_events = dsm.dpi_event_retrieve(time_type="LAST_24_HOURS", host_group_id=7, host_type="HOSTS_IN_GROUP")


dsm.end_session()