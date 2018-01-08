![alt tag](/docs/source/_static/dsp3_logo3.png?raw=true "DSP3")

DSP3
====
[![Build Status](https://travis-ci.org/jeffthorne/DSP3.svg?branch=master)](https://travis-ci.org/jeffthorne/deep_security)

A Python 3 compatible SDK for Trend Micro's Deep Security platform.

## Installation
pip install -i https://testpypi.python.org/pypi dsp3


## Documentation
http://dsp3.readthedocs.io

## Examples

To run use cases from project dir as an example: python -m examples.alerts<br/>

1. Authentication: [examples/authentication.py](examples/authentication.py)
2. Get events: [examples/get_events.py](examples/get_events.py)
3. Create block by file hash rules: [examples/block_by_hash.py](examples/block_by_hash.py)
4. Get manager info: [examples/manager_info.py](examples/manager_info.py)
5. Alerts: [examples/alerts.py](examples/alerts.py)

## Use Cases
The following examples are some use cases seen in the field.<br/>
To run use cases from project dir: python -m usecases.eventscsv

1. Retrieve events to csv files: [usecases/eventscsv.py](usecases/eventscsv.py)
