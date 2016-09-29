class TimeFilter:
    """Represents a Deep Security TimeFilter Transport"""
    def __init__(self, rangeFrom, rangeTo, specificTime, type):
        self.rangeFrom = rangeFrom
        self.rangeTo = rangeTo
        self.specificTime = specificTime
        self.type = type