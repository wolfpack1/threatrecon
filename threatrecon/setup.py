from distutils.core import setup

setup(
    name='ThreatRecon',
    version='1.0.0',
    author='Wapack Labs',
    author_email='chall@wapacklabs.com',
    packages=['threatrecon', ],
    scripts=['bin/stowe-towels.py','bin/wash-towels.py'],
    url='http://pypi.python.org/pypi/TowelStuff/',
    license='LICENSE.txt',
    description='Useful towel-related stuff.',
    long_description=open('README.txt').read(),
    install_requires=[
        "python-dateutil >= 2.2",
    ],
)
