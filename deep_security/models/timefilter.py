from suds import Client

class TimeFilter:
    """Represents a Deep Security TimeFilter Transport"""
    def __init__(self, suds_client, rangeFrom=None, rangeTo=None, specificTime=None, time_type="LAST_HOUR"):
        self.rangeFrom = rangeFrom
        self.rangeTo = rangeTo
        self.specificTime = specificTime
        self.client = suds_client
        self.time_type = time_type

    def get_transport(self):
        tft = self.client.factory.create('TimeFilterTransport')
        tft.rangeFrom = self.rangeFrom
        tft.rangeTo = self.rangeTo
        tft.specificTime = self.specificTime

        etft = self.client.factory.create('EnumTimeFilterType')

        types = {"LAST_HOUR": etft.LAST_HOUR,
                 "LAST_24_HOURS": etft.LAST_24_HOURS,
                 "LAST_7_DAYS": etft.LAST_7_DAYS,
                 "CUSTOM_RANGE": etft.CUSTOM_RANGE,
                 "SPECIFIC_TIME": etft.SPECIFIC_TIME}

        if types[self.time_type]:
            tft.type = types[self.time_type]
        elif self.rangeFrom is not None and self.rangeTo is not None:
            tft.type = etft.CUSTOM_RANGE
        elif self.specificTime is not None:
            tft.type = etft.SPECIFIC_TIME
        else:
            tft.type = etft.LAST_HOUR

        return tft
