from distutils.core import setup

setup(
    name='megad-mqtt-gw',
    version='0.3',
    description='Gateway between MQTT queue and MegaD devices (http://ab-log.ru)',
    author='rs',
    author_email='repalov@gmail.com',
    url='https://github.com/repalov/megad-mqtt-gw',
    license='Apache License',
    classifiers=[
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Topic :: System :: Networking',
        'License :: OSI Approved :: Apache Software License',
    ],
    packages=['megad'],
    install_requires=['aiohttp>=3.4.4', 'paho-mqtt>=1.4', 'netifaces>=0.10.7'],
    data_files=[('/etc', ['megad-mqtt-gw.homeassistant.conf', 'megad-mqtt-gw.wirenboard.conf']),
                ('/lib/systemd/system', ['megad-mqtt-gw.service'])
                ],
    entry_points={'console_scripts': ['megad-mqtt-gw=megad.megad_mqtt_gw:main']}
)
