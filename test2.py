from models.manager import Manager
from datetime import datetime

dsm = Manager("admin", "Trendmicro2008!")
rangeFrom = datetime(2016, 9, 23, 11, 00)
rangeTo = datetime(2016, 9, 23, 11, 44)
dsm.antimalware_event_retreive(rangeFrom, rangeTo)
dsm.end_session()