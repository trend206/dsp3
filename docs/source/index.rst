.. deep_security documentation master file, created by
   sphinx-quickstart on Wed Nov  2 16:08:12 2016.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to DSP3
=========================================

Welcome to DSP3's documentation.


Installation
-----------------

| pip install -i https://testpypi.python.org/pypi deep_security
| note: This project is an early stage effor and is currently hosted at testpypi


Getting Started
-----------------
| Start by creating a DSM manager object. This manager represents the DSM API endpoint.
|
| from dsp3.models.manager import Manager
| dsm = Manager("username", "password", "tenant")   #DSaS Example
| or
| dsm = Manager("username", "password", "hostname", "port")   #On Prem DSM Example


Indices and tables
==================

* :ref:`genindex`
* :ref:`modindex`
* :ref:`search`

