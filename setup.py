#!/usr/bin/env python3
"""
Setup script
"""

from setuptools import find_packages, setup

setup(
    name="salt-passbolt",
    version="1.0.0",
    packages=find_packages("src"),
    package_dir={'': 'src'},
    include_package_data=True,
    install_requires=[
        "passbolt-python-api>=0.1.2",
    ],
    author="Sven Seeberg (Netzbegrünung e.V.)",
    author_email="mail@sven-seeberg.de",
    description="Fetch passwords from Passbolt to build Saltstack pillars",
    license="MIT",
    keywords="Passbolt Salt Pillar",
    url="http://github.com/netzbegruenung/salt-passbolt",
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
    ]
)
