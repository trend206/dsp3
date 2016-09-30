from suds import Client
from zeep import Client

class Host:
    """Represents a Deep Security Host"""
    def __init__(self, ID, name, description, displayName, external, externalID, hostGroupID, hostType, platform, securityProfileID):
        self.id = ID
        self.name = name
        self.description = description
        self.displayName = displayName
        self.external = external
        self.externalID = externalID
        self.hostGroupID = hostGroupID
        self.hostType = hostType
        self.platform = platform
        self.securityProfileId = securityProfileID


class HostFilter:
    def __init__(self, hostGroupId=None, hostId=None, securityProfileId=None, type="ALL_HOSTS"):
        self.hostGroupID = hostGroupId
        self.hostID = hostId
        self.securityProfileID = securityProfileId
        self.type = type  #EnumHostFilterType

    def convert_to_host_filter(self, suds_client:Client):
        hft = suds_client.factory.create('HostFilterTransport')
        hft.hostGroupID = self.hostGroupID
        hft.hostID = self.hostID
        hft.securityProfileID = self.securityProfileID
        ehft = suds_client.factory.create('EnumHostFilterType')
        hft.type = ehft.ALL_HOSTS
        return hft
