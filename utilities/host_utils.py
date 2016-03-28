from models.host import Host

def create_host(hostTransport) -> Host:
    host = Host(hostTransport.ID, hostTransport.name, hostTransport.description, hostTransport.displayName, hostTransport.external, \
                hostTransport.externalID, hostTransport.hostGroupID, hostTransport.hostType, hostTransport.platform, \
                hostTransport.securityProfileID)
    return host