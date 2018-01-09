from dsp3.models.manager import Manager


# authenticate to DSaS
dsm = Manager(username="username", password="password", tenant="ACME Corp")

# list event based tasks
event_tasks = dsm.event_based()

# delete an event based task
resp = dsm.event_based_delete(205)

#end session
dsm.end_session()