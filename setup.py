from distutils.core import setup

setup(
    name='megad-mqtt-gw',
    version='0.1',
    description='Gateway between MQTT queue and MegaD devices (http://ab-log.ru)',
    author='rs',
    author_email='repalov@gmail.com',
    url='https://github.com/repalov/megad-mqtt-gw',
    license='Apache License',
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Environment :: Console',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: Apache Software License',
    ],
    install_requires=['aiohttp>=1.3.1', 'lxml>=3.7.3', 'paho-mqtt>=1.2'],
    scripts=['megad-mqtt-gw.py'],
    data_files=[('/etc', ['megad-mqtt-gw.conf']), ('/lib/systemd/system', ['megad-mqtt-gw.service'])]
)
