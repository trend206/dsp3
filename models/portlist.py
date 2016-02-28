class PortList:
    """Represents a Deep Security Port List"""
    def __init__(self, id, name, description, ports, tbuid):
        self.id = id
        self.name = name
        self.description = description
        self.ports = ports
        self.tbuid = tbuid