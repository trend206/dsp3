from dsp3.models.manager import Manager


# authenticate to DSaS
dsm = Manager(username="username", password="password", tenant="ACME Corp")

# list report templates
reports = dsm.reports()


dsm.end_session()