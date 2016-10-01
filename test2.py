from models.manager import Manager
from datetime import datetime

dsm = Manager("admin", "password")
#range_from = datetime(2016, 9, 30, 14, 44)
#range_to = datetime(2016, 9, 30, 15, 58)
dsm.antimalware_event_retreive(host_id=64, time_type="LAST_24_HOURS")
dsm.end_session()