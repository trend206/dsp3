from dsp3.models.manager import Manager


dsm = Manager(username='username', password='password',host="127.0.0.1", port="4119")

# get detail for a specific host by id
host = dsm.host_detail_retrieve(host_id=11)

# clear error and warnings for a host
dsm.host_clear_warnings_and_errors([11])

# initiate recommendation scans for a list of hosts by id
dsm.host_recommendation_scan([11, 12, 14])

# Immediately initiates the fetch of events from hosts identified by IDs. does not retrieve events
dsm.host_getevents_now(11)

# retrieve all hosts
hosts = dsm.host_retrieve_all()

# retrieve antimalware events for a specific host
am_events = dsm.antimalware_event_retrieve(host_id=11, host_type="SPECIFIC_HOST", time_type="LAST_24_HOURS")

# end dsm session
dsm.end_session()
