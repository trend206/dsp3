from datetime import datetime, timezone
import requests
import json

class TimeRange:
    #TODO: need to handle defualt paramaters and the call to timestamp()
    def __init__(self, end: datetime = 0, start: datetime = 0):
        self.end = end
        self.start = start

    def to_json(self):
        return dict(end=int(self.end.timestamp()), start=int(self.start.timestamp()))


class PropertyFilter:

    def __init__(self, file_name: str, host_name: str):
        self.file_name = file_name
        self.host_name = host_name

    def to_json(self):
        return dict(fileName=self.file_name, hostName=self.host_name)


class Scope:
    """
    Name            Type            Required    Description
    filter	        PropertyFilter	Yes		    The optional filters with which to limit the query.
    hostGroupID	    Number	        No		    Get the host group ID that this query should be scoped by.
    smartFolderID	Number	        No		    Get the smart folder ID that this query should be scoped by.
    timeRange	    TimeRange	    Yes		    The time range with which to limit the query.

    """
    def __init__(self, filter:PropertyFilter, time_range: TimeRange, host_group_id = 0, smart_folder_id = None):
        self.filter = filter
        self.time_range = time_range
        self.host_group_id = host_group_id
        self.smart_folder_id = smart_folder_id

    def to_json(self):
        return dict(filter=self.filter.to_json(), timeRange=self.time_range.to_json())


class LiftApplicationDriftRequest:

    def __init__(self, scope):
        self.scope = scope

    def to_json(self):
        return json.dumps(dict(ListApplicationDriftRequest=dict(scope=self.scope.to_json())))


class AddGlobalRulesetRulesRequest:

    def __init__(self, hash, description=""):
        self.hash = hash
        self.description = description

    def to_json(self):
        return json.dumps(dict(AddGlobalRulesetRulesRequest=dict(rules=[dict(sha256=self.hash, action="block", description=self.description)])))

