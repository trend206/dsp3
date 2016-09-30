from models.manager import Manager
from datetime import datetime

dsm = Manager("admin", "password")
rangeFrom = datetime(2016, 9, 30, 10, 15)
rangeTo = datetime(2016, 9, 30, 11, 16)
dsm.antimalware_event_retreive(rangeFrom, rangeTo)
dsm.end_session()