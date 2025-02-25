# Canary

[![PyPI version](https://badge.fury.io/py/canary-pkg-whoward3.svg)](https://badge.fury.io/py/canary-pkg-whoward3)

A Python Package developed as part of CEDARs Project Canary to enable the rapid simulation of Distributed DDoS Detection techniques using CORE.

See the LICENSE file included in this distribution.

## Get Started

1. Clone this repository
2. Install CORE v.5.4.0
3. Update the ``core.conf`` to point the  ``custom_services_dir =`` to the ``../canaryServices`` directory in this repository
4. Open a bash terminal in the repositories root directory
5. Run ``python3 setup.py install --user`` to install the package
6. Run the tests via ``python3 -m tests.test_canary``
7. If all tests pass ``OK`` your good to go!

## Usage

All the scripts in canaryScripts can be run independently or in conjunction depending on the use case. Scripts can be run from the terminal or loaded into the CORE GUI using the ``Execute Python script with options`` button. Use the ``canary_driver.py`` script to orchestrate the execution of multiple simulations. For more see the [wiki](https://github.com/whoward3/Canary/wiki/home).
