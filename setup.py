# -*- coding: utf-8 -*-
# Based on original work by JoryPein — https://github.com/JoryPein/BurpSuite-HAR-Exporter (MIT)
from setuptools import setup

packages = \
['burp2har']

package_data = \
{'': ['*']}

install_requires = \
['typer>=0.9.0', 'rich>=10.0.0']

entry_points = \
{'console_scripts': ['burp2har = burp2har.cli:run']}

setup_kwargs = {
    'name': 'burp2har',
    'version': '0.2.0',
    'description': 'Convert Burp Suite XML exports to HAR format',
    'long_description': open('readme.md', encoding='utf-8').read(),
    'long_description_content_type': 'text/markdown',
    'author': 'Lorenzo Surico',
    'author_email': '',
    'maintainer': 'Lorenzo Surico',
    'maintainer_email': '',
    'url': 'https://github.com/xlory04/BurpSuite-HAR-Exporter',
    'license': 'MIT',
    'packages': packages,
    'package_data': package_data,
    'install_requires': install_requires,
    'entry_points': entry_points,
    'python_requires': '>=3.8,<4.0',
    'classifiers': [
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Topic :: Security',
        'Topic :: Internet :: WWW/HTTP',
        'Environment :: Console',
    ],
}


setup(**setup_kwargs)
