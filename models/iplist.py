class IPList:
    """Represents a Deep Security IPList"""
    def __init__(self, id, name, description, ips):
        self.id = id
        self.name = name
        self.description = description
        self.ips = ips
