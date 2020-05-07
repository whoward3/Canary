"""
Canary
Description: A collection of python scripts for distributed DDoS Detection Simulations using CORE
Author: Winston Howard
Created Date: 04/24/20

 
Canary
Copyright (C) 2020  Winston Howard

See the LICENSE file included in this distribution.
"""

import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="canary-pkg-whoward3",
    version="1.0.1",
    author="Winston Howard",
    author_email="winston.howard@yahoo.com",
    description="A collection of python scripts for distributed DDoS Detection Simulations using CORE",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/whoward3/canary",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Operating System :: POSIX :: Linux",
    ],
    python_requires='>=3.6',
)