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
|


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
Please refer to the Manager api doc at :doc:`dsp3.models.manager` for dsp3 capabilities.


1. Authentication: `github <https://github.com/jeffthorne/DSP3/blob/master/examples/authentication.py/>`_.
2. Get events: `github <https://github.com/jeffthorne/DSP3/blob/master/examples/get_events.py/>`_.
3. Create block by file hash rules: `github <https://github.com/jeffthorne/DSP3/blob/master/examples/block_by_hash.py/>`_.


All code Examples can be found on `github <https://github.com/jeffthorne/DSP3/tree/master/examples/>`_