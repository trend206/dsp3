.. deep_security documentation master file, created by
   sphinx-quickstart on Wed Nov  2 16:08:12 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directives...


|
Welcome to DSP3
===============

Welcome to DSP3's documentation.


Installation
------------

.. code-block:: python

   pip install -i https://testpypi.python.org/pypi dsp3

This project is an early stage effort and is currently hosted at testpypi.

|
| Note: Requires Python 3.5.2 or higher due to reliance on Python's typing module.
| Type hints were included to assist SEs or users new to the field of programming.


Getting Started
---------------
Start by creating a DSM manager object. This manager represents the DSM API endpoint

.. code-block:: python

   from dsp3.models.manager import Manager

   dsm = Manager(username="username", password="password", tenant="tenant")   #DSaS Example
   dsm = Manager(username="username", password="password", host="hostname", port="port")   #On Prem DSM Example


Be sure to close the manager session when finished to avoid exceeding connection limits.

.. code-block:: python

   dsm.end_session()




Example Usage
--------------
Here is some example DSP3 api calls. Please refer to the Manager api doc at :doc:`dsp3.models.manager` for
full capabilities at this time.

More code Examples can be found here `<https://github.com/jeffthorne/DSP3/tree/master/examples/>`_

Example 1: Retreive all port lists from the DSM. 

.. code-block:: python

   port_lists = dsm.get_port_lists_all()


Example 2: Get JVM statistics.

.. code-block:: python

   manager_node = "1"
   from_date = datetime(2016, 3, 2, 17, 3)
   to_date = datetime(2016, 3, 2, 17, 20)
   dsm.get_jvmusage(manager_node, from_date, to_date )

Example 3: Activate/Deactivate agents .

.. code-block:: python

   dsm.host_agent_deactivate(host12.id)   #pass single host id or list of host ids
   dsm.host_agent_activate([host12.id, host16.id])

Example 4: Retrieve AntiMalware events for a specific host over the last 24 hours

.. code-block:: python

   dsm.antimalware_event_retreive(host_id=64, time_type="LAST_24_HOURS")
