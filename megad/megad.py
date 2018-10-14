#!/usr/bin/env python3
import asyncio
import json
import re
import socket
from enum import IntEnum

import aiohttp
import aiohttp.web
import aiohttp.web_server
import netifaces


class PortType(IntEnum):
    NC = 255
    In = 0
    Out = 1
    ADC = 2
    DSen = 3
    I2C = 4


class PortOutMode(IntEnum):
    Switch = 0
    PWM = 1
    DS2413 = 2
    SwitchLink = 3


class PortDSenDevice(IntEnum):
    DHT11 = 1
    DHT22 = 2
    OneW = 3
    iB = 4
    OneWBUS = 5
    W26 = 6


class PortI2CMode(IntEnum):
    NC = 0
    SDA = 1
    SCL = 2


class PortI2CSDADevice(IntEnum):
    ANY = 0
    HTU21D = 1
    BH1750 = 2
    TSL2591 = 3
    SSD1306 = 4
    BMP180 = 5
    BMx280 = 6
    MAX44009 = 7
    MCP230XX = 20
    PCA9685 = 21


class Device(object):
    def _parse_port_html(self, response_body):
        def extract_attrs(s):
            attrs = {}
            for a in s.split(' '):
                a_idx = a.find('=')
                if a_idx >= 0:
                    val = a[a_idx + 1:]
                    if len(val) > 0 and val[0] in ['"', "'"]:
                        val = val[1:-1]
                    attrs[a[:a_idx]] = val
            return attrs

        props = {}
        for it in re.finditer(r'<input ([^>]+)>', response_body):
            it_attrs = extract_attrs(it.group(1))
            if 'name' in it_attrs and 'value' in it_attrs:
                props[it_attrs['name']] = it_attrs['value']
        for it in re.finditer(r'<select\s+name=([^>]+)>(.*?)</select>', response_body):
            m = re.search(r'<option([^>]*)selected([^>]*)>', it.group(2))
            if m:
                opt_attrs = extract_attrs(m.group(1))
                opt_attrs.update(extract_attrs(m.group(2)))
                if 'value' in opt_attrs:
                    props[it.group(1)] = opt_attrs['value']

        for name in ('pn', 'pty', 'd', 'm'):
            if name in props:
                props[name] = int(props[name])
        return props

    def _parse_port_value(self, port, value):
        port_type = port.get('pty')
        if port_type is None and port.get('type') == 'ADC':
            # for MegaD-328
            port_type = PortType.ADC
        port_mode = port.get('m')
        port_dev = port.get('d')

        if value is None:
            return None

        if port_type == PortType.NC:
            return None

        if port_type == PortType.In:
            if isinstance(value, str):
                if value.startswith('OFF'):
                    return 'OFF'
                if value.startswith('ON'):
                    return 'ON'
                if value.isnumeric():
                    value = int(value)
            if isinstance(value, int):
                if value == 0:
                    return 'ON'
                if value == 1:
                    return 'OFF'
                if value == 2:
                    return 'LONG'
            self.platform.logger.warning(f'Unknown port mode/device: {port}. Value of type {type(value)} unparsed: {value}')
            return value

        if port_type == PortType.Out:
            if port_mode == PortOutMode.Switch or port_mode is None:
                if isinstance(value, str):
                    if value.startswith('OFF'):
                        return 0
                    if value.startswith('ON'):
                        return 1
                    if value.isnumeric():
                        value = int(value)
                if isinstance(value, int):
                    if value == 0 or value == 1:
                        return value
            if port.get('m') == PortOutMode.PWM:
                if isinstance(value, str):
                    value = int(value)
                return value
            self.platform.logger.warning(f'Unknown port mode/device: {port}. Value of type {type(value)} unparsed: {value}')
            return value

        if port_type == PortType.ADC:
            return float(value)

        if port_type == PortType.DSen:
            if port_dev == PortDSenDevice.OneWBUS:
                if value == 'busy' or value == '':
                    return None
                return json.dumps({v.split(':')[0]: float(v.split(':')[1]) for v in value.split(';')})
            self.platform.logger.warning(f'Unknown port mode/device: {port}. Value of type {type(value)} unparsed: {value}')
            return value

        if port_type == PortType.I2C:
            if port_mode == PortI2CMode.NC:
                return None
            if port_mode == PortI2CMode.SCL:
                return None
            if port_mode == PortI2CMode.SDA:
                if port_dev == PortI2CSDADevice.BMx280:
                    return json.dumps({v.split(':')[0]: float(v.split(':')[1])  for v in value.split('/')})
                if port_dev == PortI2CSDADevice.MAX44009:
                    return float(value)
                if port_dev == PortI2CSDADevice.TSL2591:
                    return float(value)
            self.platform.logger.warning(f'Unknown port mode/device: {port}. Value of type {type(value)} unparsed: {value}')
            return value

        self.platform.logger.warning(f'Unknown port type: {port}. Value of type {type(value)} unparsed: {value}')
        return value

    async def _fetch(self, url):
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                if resp.status == 200:
                    return await resp.text()
        return ''

    def __init__(self, platform, config):
        self.platform = platform
        self.address = config['address']
        self.password = config['password']
        self.device_base_url = f'http://{self.address}/{self.password}/'
        self.mega_cf_checked = False
        self.mega_id = None
        self.mega_cf = None
        self.device_id = None
        self.device_name = None
        self.ports = None

    async def query_device(self):
        try:
            # query MegaID
            megaid_html = await self._fetch(f'http://{self.address}/{self.password}/?cf=2')
            m = re.search(r'<input[^>]+name=mdid\s[^>]+value="([^"]*)">', megaid_html)
            megaid = m.group(1) if m and len(m.group(1)) > 0 else self.address.replace('.', '_')

            # read megad configuration (for later checking)
            megacf_html = await self._fetch(f'http://{self.address}/{self.password}/?cf=1')
            megacf = {}
            for it in re.finditer(r'<input[^>]+name=([^> ]+)\s[^>]*value=([^> ]+)>', megacf_html):
                megacf[it.group(1)] = it.group(2).strip('"')

            # read ports configuration
            megaver_html = await self._fetch(f'http://{self.address}/{self.password}/')
            megaver = 328
            if 'MegaD-2561' in megaver_html:
                megaver = 2561

            ports = {}
            if megaver == 328:
                ports_html = await self._fetch(f'http://{self.address}/{self.password}')
                for it in re.finditer(r'<a href=([^<>]*?\?pt=.*?)>(.*?)\s*-\s*(.*?)</a>', ports_html):
                    port_html = await self._fetch(f'http://{self.address}{it.group(1)}')
                    port_props = self._parse_port_html(port_html)
                    port_props['name'] = it.group(2)
                    port_props['type'] = it.group(3)
                    if 'pn' in port_props:
                        ports[f'p{port_props["pn"]}'] = port_props
                    else:
                        self.platform.logger.warning(f'incorrect or unsupported port description received from '
                                                     f'address http://{self.address}{it.group(1)}')
            elif megaver == 2561:
                for port_list_url in ['/', '/?cf=3', '/?cf=4']:
                    ports_html = await self._fetch(f'http://{self.address}/{self.password}{port_list_url}')
                    for it in re.finditer(r'<a href=([^<>]*?\?pt=.*?)>(.*?)\s*-\s*(.*?)</a>', ports_html):
                        port_html = await self._fetch(f'http://{self.address}{it.group(1)}')
                        port_props = self._parse_port_html(port_html)
                        port_props['name'] = it.group(2)
                        port_props['type'] = it.group(3)
                        if 'pn' in port_props:
                            ports[f'p{port_props["pn"]}'] = port_props
                            self.platform.logger.debug(f'Query device: Device: {self.device_id} Port: {port_props}')
                        else:
                            self.platform.logger.warning(f'incorrect or unsupported port description received from '
                                                         f'address http://{self.address}{it.group(1)}')

            self.mega_id, self.mega_cf, self.ports = megaid, megacf, ports
            if self.device_id is None:
                self.device_id = f'megad_{self.mega_id}'
            if self.device_name is None:
                self.device_name = f'MegaD {self.mega_id} ({self.address})'

            await self.pool()
        except (aiohttp.ClientError, asyncio.TimeoutError) as e:
            self.mega_id, self.mega_cf, self.ports = None, None, None
            self.device_id, self.device_name = None, None

    def check_config(self):
        # <input name=sip value=192.168.1.110:19780>
        # <input name=sct maxlength=15 value="megad">
        result = []
        if self.mega_cf_checked:
            return result
        if 'sip' in self.mega_cf and '_local_ip' in self.mega_cf and \
                        self.mega_cf['sip'].split(':')[0] != self.mega_cf['_local_ip']:
            result.append('MegaD {} server IP is incorrect (configured {}, but must be {})'.format(
                self.mega_id, self.mega_cf['sip'].split(':')[0], self.mega_cf['_local_ip']))
        if 'sct' in self.mega_cf and self.mega_cf['sct'] != 'megad':
            result.append('MegaD {} script is incorrect (configured {}, but must be "megad")'.format(
                self.mega_id, self.mega_cf['sct']))
        self.mega_cf_checked = True
        return result

    async def pool(self):
        updated = set()
        state = await self._fetch(self.device_base_url + '?cmd=all')
        for idx, val in enumerate(state.split(';')):
            p_name = f'p{idx}'
            if p_name in self.ports:
                cur_port = self.ports[p_name]
                val = self._parse_port_value(cur_port, val)
                if val is not None and ('value' not in cur_port or cur_port['value'] != val):
                    cur_port['value'] = val
                    updated.add(p_name)

        # ports does not transmitted in cmd=all response
        for p_name, cur_port in self.ports.items():
            if cur_port.get('pty') == PortType.DSen and cur_port.get('d') == PortDSenDevice.OneWBUS:
                val = await self._fetch(self.device_base_url + f'?pt={cur_port["pn"]}&cmd=list')
                val = self._parse_port_value(cur_port, val)
                if val is not None and ('value' not in cur_port or cur_port['value'] != val):
                    cur_port['value'] = val
                    updated.add(p_name)

        return updated

    async def send_message(self, control, command):
        self.platform.logger.debug(f'Send message to device {self.device_id} for control {control} with command {command}')

        async with aiohttp.ClientSession() as session:
            async with session.get(f'{self.device_base_url}?cmd={control[1:]}:{command}') as resp:
                if resp.status != 200:
                    self.platform.logger.warning(f'Error at send message to device {self.device_id} for control '
                                                 f'{control} with command {command}. Response: {resp}')
                    return None
                ports_html = await resp.text()
                if ports_html == 'Done':
                    self.platform.logger.debug(f'Message sent successfully')
                    return command
                self.platform.logger.warning(f'Unexpected result at send message to device {self.device_id} for control'
                                             f' {control} with command {command}. Response text: {ports_html}')
        return None

    async def parse_message(self, parameters):
        self.platform.logger.debug(f'Message from MegaD {self.device_id} with parameters={parameters}')
        port_id = f'p{parameters.get("pt", "")}'
        cur_port = self.ports.get(port_id, None)
        if cur_port is not None:
            if cur_port.get('pty') == PortType.In:
                value = self._parse_port_value(cur_port, int(parameters.get('m', 0)))
                if value:
                    cur_port['value'] = value
                    if self.platform.on_state_changed:
                        await self.platform.on_state_changed(self.device_id, port_id, value)
                    return
        self.platform.logger.warning(f'Unknown message from MegaD with parameters={parameters}')


class DiscoveryProtocol:
    def __init__(self, loop, remote_addr=None):
        self.loop = loop
        self.remote_addr = remote_addr
        self.transport = None
        self.result = set()

    def connection_made(self, transport):
        self.transport = transport
        sock = transport.get_extra_info("socket")
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

    def datagram_received(self, data, addr):
        if len(data) >= 5 and data[0] == 0xaa:
            self.result.add(addr[0])

    def error_received(self, exc):
        pass

    def connection_lost(self, exc):
        pass

    def send_discovery(self):
        self.result = set()
        self.transport.sendto(b'\xAA\x00\x0C', self.remote_addr)   # chr(0xAA).chr(0).chr(12)


class DevicesSet(object):
    def __init__(self, platform, config):
        self.platform = platform

        self.scan_enabled = bool(config.get('scan', {}).get('enabled', 'true'))
        self.scan_interfaces = config.get('scan', {}).get('interfaces')
        self.scap_password = config.get('scan', {}).get('password', 'sec')
        self.scan_transports = {}

        cf_devices = config.get('devices', [])
        self.devices = {}
        self.disabled_devices = []
        for cf_dev in cf_devices:
            dev = Device(self.platform, cf_dev)
            self.disabled_devices.append(dev)
            self.platform.logger.info('Device {} added as disabled'.format(dev.address))

    async def discovery(self):
        if not self.scan_enabled:
            return set()

        # send broadcast messages for megadevices discovery
        for iface in self.scan_interfaces or netifaces.interfaces():
            ifaddrs = netifaces.ifaddresses(iface)
            if netifaces.AF_INET not in ifaddrs:
                continue
            for ifaddr in ifaddrs[netifaces.AF_INET]:
                if 'broadcast' not in ifaddr:
                    continue
                if ifaddr['addr'] in self.scan_transports:
                    self.scan_transports[ifaddr['addr']][1].send_discovery()
                else:
                    transport, protocol = await self.platform.loop.create_datagram_endpoint(
                        lambda: DiscoveryProtocol(self.platform.loop, remote_addr=(ifaddr['broadcast'], 52000)),
                        local_addr=(ifaddr['addr'], 42000))
                    self.scan_transports[ifaddr['addr']] = (transport, protocol)
                    protocol.send_discovery()

        # wait for response of all devices
        await asyncio.sleep(2)

        # gather all found devices
        scan_result = set()
        for _, tp in self.scan_transports.items():
            scan_result.update(tp[1].result)
        return scan_result

    async def check_disabled(self):
        scan_devices = await self.discovery()
        for sdev in scan_devices:
            found = False
            for _, dev in self.devices.items():
                if sdev == dev.address:
                    found = True
            for dev in self.disabled_devices:
                if sdev == dev.address:
                    found = True
            if not found:
                new_dev = Device(self.platform, {'address': sdev, 'password': self.scap_password})
                self.disabled_devices.append(new_dev)
                self.platform.logger.info(f'Found new device {new_dev.address}. Added as disabled')

        await asyncio.gather(*[dev.query_device() for dev in self.disabled_devices])

        for dev in self.disabled_devices.copy():  # make list copy to use remove inside the loop
            if dev.device_id is not None:
                self.devices[dev.device_id] = dev
                self.disabled_devices.remove(dev)
                self.platform.logger.info(f'Device enabled {dev.device_id}')
                if self.platform.on_device_found:
                    await self.platform.on_device_found(dev.device_id)

    async def pool(self, device_id=None):
        result = set()
        try:
            for megad_id, dev in self.devices.items():
                if device_id is None or dev.device_id == device_id:
                    updated = await dev.pool()
                    for port_id in updated:
                        if self.platform.on_state_changed:
                            await self.platform.on_state_changed(dev.device_id, port_id, dev.ports[port_id]['value'])
                        result.add((dev.device_id, port_id))
        except Exception as e:
            self.platform.logger.exception(f'Exception on HTTP MegaD message processing. Exception type: {type(e)} message: {e}')
        return result

    async def send_message(self, device, control, command):
        await self.devices[device].send_message(control, command)

    async def parse_message(self, address, parameters):
        self.platform.logger.debug(f'HTTP message from {address} with parameters {parameters}')
        dev = self.devices.get(f'megad_{address.replace(".", "_")}', None)
        if dev:
            await dev.parse_message(parameters)


class Server(object):
    def __init__(self, platform, config):
        self.platform = platform
        self.address = config.get('address', '0.0.0.0')
        self.port = config.get('port', '19780')
        self.server_http = aiohttp.web_server.Server(self.handler, loop=self.platform.loop)
        self.server_socket = None

    async def start(self):
        self.server_socket = await self.platform.loop.create_server(self.server_http, self.address, self.port)
        self.platform.logger.debug("HTTP Server started.")

    async def stop(self):
        await self.server_http.shutdown()
        self.server_http = None
        self.server_socket = None
        self.platform.logger.debug("HTTP Server stopped.")

    async def handler(self, request):
        from aiohttp.tcp_helpers import tcp_cork, tcp_nodelay

        if request.rel_url.path != '/megad':
            return aiohttp.web.Response(text="ERROR: Incorrect path")
        peername = request.transport.get_extra_info('peername')
        if peername is None:
            return aiohttp.web.Response(text="ERROR: Internal error - unknown remote address of peer")
        host, port = peername
        await self.platform.devices.parse_message(host, request.rel_url.query)

        # need to send headers and body in one packet as required by MegaD-328
        tcp_cork(request.transport, True)
        tcp_nodelay(request.transport, False)

        response = aiohttp.web.Response(text='')
        response.force_close()
        return response


class Platform:
    def __init__(self, loop, logger, config, on_device_found, on_device_lost, on_state_changed):
        self.server = None
        self.loop = loop
        self.logger = logger
        self.devices = DevicesSet(self, config)
        self.server = Server(self, config.get('server', {}))
        self.pool_interval = float(config.get('pool', 0))
        self.pool_state_interval = float(config.get('pool_state', 0.1))

        self.on_device_found = on_device_found
        self.on_device_lost = on_device_lost
        self.on_state_changed = on_state_changed

    def _async_pooling(self):
        async def pool():
            await self.devices.check_disabled()
            await self.devices.pool()
            if self.loop.is_running():
                self.loop.call_later(self.pool_interval, self._async_pooling)

        self.loop.create_task(pool())

    async def start(self):
        await self.server.start()
        if self.pool_interval > 0:
            self.loop.call_soon(self._async_pooling)

    async def stop(self):
        await self.server.stop()

    def _async_state_pooling(self, device, control):
        async def pool():
            changed = await self.devices.pool(device)
            if (device, control) in changed and self.loop.is_running():
                self.loop.call_later(self.pool_state_interval, self._async_state_pooling, device, control)

        self.loop.create_task(pool())

    async def send_message(self, device, control, message):
        await self.devices.send_message(device, control, message)
        if self.pool_state_interval > 0:
            self.loop.call_soon(self._async_state_pooling, device, control)    
