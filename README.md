deep-security-py3
======
A Python 3 compatible SDK for Trend Micro's Deep Security platform.

NOTE: This is a very initial commit and not recommended for use as of yet.


## Usage

Set initial parameters in config.py

```python

base_path = 'https://10.0.124.175'              #DSM URL
dsm_port = 4119                                 #DSM Port
soap_api_wsdl = 'webservice/Manager?WSDL'       #DSM Soap WSDL path

```



```python
from models.manager import Manager

# create a manager object. Manager represents the DSM API endpoint
dsm = Manager("username", "password")


# Example 1 - Retreive all port lists from the DSM.
port_lists = dsm.get_port_lists_all()


# close session when finished to avoid exceeding connection limits. DSM sessions are the same as user logins.
dsm.end_session()

```