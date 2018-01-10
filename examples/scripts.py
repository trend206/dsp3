from dsp3.models.manager import Manager


# authenticate to DSaS
dsm = Manager(username="username", password="password", tenant="ACME Corp")

# list scripts
scripts = dsm.scripts()



dsm.end_session()