from typing import List
from models.timefilter import TimeFilter
from suds import Client

def convert_to_tansport_time_filter(timeFilter:TimeFilter, suds_client:Client):
    tft = suds_client.factory.create('TimeFilterTransport')
    tft.rangeFrom = timeFilter.rangeFrom
    tft.rangeTo = timeFilter.rangeTo
    tft.specificTime = timeFilter.specificTime
    etft = suds_client.factory.create('EnumTimeFilterType')
    tft.type = etft.CUSTOM_RANGE
    return tft