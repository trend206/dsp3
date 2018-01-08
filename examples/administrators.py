from dsp3.models.manager import Manager


dsm = Manager(username="username", password="password", tenant="ACME Corp")

# list administrators
admins = dsm.administrators(admin_id=1, admin_op="eq")['ListAdministratorsResponse']['administrators']

# get admin where id = 1
admins = dsm.administrators(admin_id=1, admin_op="eq")['ListAdministratorsResponse']['administrators']


# get admin where id > 1
admins = dsm.administrators(admin_id=1, admin_op="gt")['ListAdministratorsResponse']['administrators']

dsm.end_session()