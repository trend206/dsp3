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