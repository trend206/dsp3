

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
    def __init__(self, client, hostGroupId=None, host_id=None, securityProfileId=None, type=None):
        self.hostGroupID = hostGroupId
        self.hostID = host_id
        self.securityProfileID = securityProfileId
        self.type = type  #EnumHostFilterType
        self.client = client

    def get_transport(self):
        hft = self.client.factory.create('HostFilterTransport')
        hft.hostGroupID = self.hostGroupID
        hft.hostID = self.hostID
        hft.securityProfileID = self.securityProfileID

        ehft = self.client.factory.create('EnumHostFilterType')
        types = {"ALL_HOSTS": ehft.ALL_HOSTS,
                 "HOSTS_IN_GROUP": ehft.HOSTS_IN_GROUP,
                 "HOSTS_USING_SECURITY_PROFILE": ehft.HOSTS_USING_SECURITY_PROFILE,
                 "HOSTS_IN_GROUP_AND_ALL_SUBGROUPS": ehft.HOSTS_IN_GROUP_AND_ALL_SUBGROUPS,
                 "SPECIFIC_HOST": ehft.SPECIFIC_HOST,
                 "MY_HOSTS": ehft.MY_HOSTS}

        if self.type is not None and types[self.type]:
            hft.type = types[self.type]
        elif self.hostID is not None:
            hft.type = ehft.SPECIFIC_HOST
        elif self.hostGroupID is not None:
            hft.type = ehft.HOSTS_IN_GROUP_AND_ALL_SUBGROUPS
        elif self.securityProfileID is not None:
            hft.type = ehft.HOSTS_USING_SECURITY_PROFILE
        else:
            hft.type = ehft.ALL_HOSTS

        return hft
