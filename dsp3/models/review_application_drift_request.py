from datetime import datetime
import requests
import json

class TimeRange:
    #TODO: need to handle defualt paramaters and the call to timestamp()
    def __init__(self, end: datetime = 0, start: datetime = 0):
        self.end = end
        self.start = start

    def to_json(self):
        return dict(end=self.end.timestamp(), start=self.start.timestamp())


class PropertyFilter:

    def __init__(self, file_name: str, host_name: str):
        self.file_name = file_name
        self.host_name = host_name

    def to_json(self):
        return dict(fileName=self.file_name, hostName=self.host_name)


class Scope:
    def __init__(self, filter:PropertyFilter, time_range: TimeRange, host_group_id = 0, smart_folder_id = None):
        self.filter = filter
        self.time_range = time_range
        self.host_group_id = host_group_id
        self.smart_folder_id = smart_folder_id

    def to_json(self):
        return dict(filter=self.filter.to_json(), timeRange=self.time_range.to_json())


class ReviewApplicationDriftRequest:

    def __init__(self, scope: Scope, action: str ='allow'):
        self.scope = scope
        self.action = action

    def to_json(self):
        return json.dumps(dict(ReviewApplicationDriftRequest=dict(scope=self.scope.to_json(), action=self.action)))


class DescribeApplicationRequest:

    def __init__(self, scope):
        self.scope = scope

    def to_json(self):
        return json.dumps(dict(DescribeApplicationRequest=dict(scope=self.scope.to_json())))



