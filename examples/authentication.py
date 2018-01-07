from dsp3.models.manager import Manager

# Example 1: Authenticate to an on-prem DSM
dsm = Manager(username="username", password="password", host="127.0.0.1", port="4119")
dsm.end_session()

# Example 2: Authenticate to DSaS with optional verify_ssl argument
dsm = Manager(username="username", password="password", tenant="tenant", verify_ssl=True)
dsm.end_session()

