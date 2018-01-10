from dsp3.models.manager import Manager


# authenticate to DSaS
dsm = Manager(username="username", password="password", tenant="ACME Corp")

# list relays
relays = dsm.list_relays()


dsm.end_session()