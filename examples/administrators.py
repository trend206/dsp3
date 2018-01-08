from dsp3.models.manager import Manager

dsm = Manager(username="username", password="password", tenant="ACME Corp")

# list administrators
admins = dsm.admistrators()

dsm.end_session()