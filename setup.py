from setuptools import setup 

setup(
    name='threatrecon',
    version='1.0.2',
    author='Wapack Labs',
    author_email='chall@wapacklabs.com',
    packages=['threatrecon', ],
    description='Python API module for Wapack Labs ThreatRecon service.',
    install_requires=[
        "python-dateutil >= 2.2",
    ],
)
