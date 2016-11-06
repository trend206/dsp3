.. deep_security documentation master file, created by
   sphinx-quickstart on Wed Nov  2 16:08:12 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive..

|
Welcome to DSP3
=========================================

Welcome to DSP3's documentation.


Installation
-----------------

.. code-block:: python

   pip install -i https://testpypi.python.org/pypi dsp3
This project is an early stage effort and is currently hosted at testpypi


Getting Started
-----------------
Start by creating a DSM manager object. This manager represents the DSM API endpoint

.. code-block:: python

   from dsp3.models.manager import Manager

   dsm = Manager("username", "password", "tenant")   #DSaS Example
   dsm = Manager("username", "password", "hostname", "port")   #On Prem DSM Example


Be sure to close the manager session when finished to avoid exceeding connection limits.

.. code-block:: python

   dsm.end_session()


Please refer to the Manager docs at :doc:`dsp3.models.manager` for full capabilities.



