from dsp3.models.manager import Manager


dsm = Manager(username="username", password="password", tenant="ACME Corp")


# retrieve all alerts
alerts = dsm.alerts()['ListAlertsResponse']['alerts']

# include alerts that have been dismissed
alerts = dsm.alerts(dismissed=True)['ListAlertsResponse']['alerts']

# retrieve alerts with an id >= 17601
alerts = dsm.alerts(dismissed=True, alert_id=17601, op="ge")['ListAlertsResponse']['alerts']


# close session
dsm.end_session()