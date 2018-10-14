#!/usr/bin/env python3
import asyncio

import paho.mqtt.client as mqtt

############################################################################
#             AsyncIO connector for MQTT protocol library                  #
############################################################################


MQTT_PROTOCOL_31 = '3.1'
MQTT_PROTOCOL_311 = '3.1.1'

MQTT_DEFAULT_PORT = 1883
MQTT_DEFAULT_KEEPALIVE = 60
MQTT_DEFAULT_QOS = 0
MQTT_DEFAULT_RETAIN = False
MQTT_DEFAULT_PROTOCOL = MQTT_PROTOCOL_311

MAX_RECONNECT_WAIT = 300  # seconds


def _raise_on_error(result):
    if result != 0:
        raise Exception('Error talking to MQTT: {}'.format(mqtt.error_string(result)))


class MQTTConnector(object):
    def __init__(self, loop, logger, config, async_on_connect, async_on_message):
        self.loop = loop
        self.logger = logger

        self.broker = config.get('address')
        self.port = int(config.get('port', '1883')) # 8883 for SSL
        self.keepalive = bool(config.get('keepalive', 'true'))
        self.async_on_connect_cb = async_on_connect
        self.async_on_message_cb = async_on_message
        self._paho_lock = asyncio.Lock(loop=self.loop)
        self._mqttc = mqtt.Client(config.get('client_id', ''),
                                  protocol=mqtt.MQTTv31 if config.get('protocol', MQTT_PROTOCOL_311) == MQTT_PROTOCOL_31 else mqtt.MQTTv311)
        if 'username' in config and 'password' in config:
            self._mqttc.username_pw_set(config['username'], config['password'])
        if 'certificate' in config:
            self._mqttc.tls_set(config['certificate'], certfile=config.get('client_cert'), keyfile=config.get('client_key'))
        if 'tls_insecure' in config:
            self._mqttc.tls_insecure_set(bool(config['tls_insecure']))
        self._mqttc.on_connect = self._mqtt_on_connect
        self._mqttc.on_disconnect = self._mqtt_on_disconnect
        self._mqttc.on_message = self._mqtt_on_message

    async def start(self):
        self._mqttc.connect_async(self.broker, self.port, self.keepalive)
        return self.loop.run_in_executor(None, self._mqttc.loop_start)

    async def stop(self):
        self._mqttc.disconnect()
        self._mqttc.loop_stop()

    async def async_subscribe(self, topic, qos=MQTT_DEFAULT_QOS):
        async with self._paho_lock:
            result, mid = await self.loop.run_in_executor(None, self._mqttc.subscribe, topic, qos)
            await asyncio.sleep(0, loop=self.loop)
        _raise_on_error(result)

    async def async_unsubscribe(self, topic):
        async with self._paho_lock:
            result, mid = await self.loop.run_in_executor(None, self._mqttc.unsubscribe, topic)
            await asyncio.sleep(0, loop=self.loop)
        _raise_on_error(result)

    async def async_publish(self, topic, payload, qos=MQTT_DEFAULT_QOS, retain=MQTT_DEFAULT_RETAIN):
        async with self._paho_lock:
            await self.loop.run_in_executor(None, self._mqttc.publish, topic, payload, qos, retain)

    def _async_add_job(self, target, *args):
        if asyncio.iscoroutine(target):
            self.loop.create_task(target)
        elif asyncio.iscoroutinefunction(target):
            self.loop.create_task(target(*args))
        else:
            self.loop.run_in_executor(None, target, *args)

    def _mqtt_on_connect(self, _mqttc, _userdata, _flags, result_code):
        if result_code != mqtt.CONNACK_ACCEPTED:
            self.logger.error('Unable to connect to the MQTT broker: %s', mqtt.connack_string(result_code))
            self._mqttc.disconnect()
            return
        self.logger.debug("Connected to MQTT.")
        if self.async_on_connect_cb is not None:
            self.loop.call_soon_threadsafe(self._async_add_job, self.async_on_connect_cb)

    def _mqtt_on_disconnect(self, _mqttc, _userdata, result_code):
        self.logger.debug("Disconnected from MQTT. Result code: {} ({}) ".format(mqtt.error_string(result_code), result_code))

    def _mqtt_on_message(self, _mqttc, _userdata, msg):
        if self.async_on_message_cb is not None:
            self.loop.call_soon_threadsafe(self._async_add_job, self.async_on_message_cb, msg.topic, msg.payload)


############################################################################
#                                                                          #
############################################################################


class Templates(object):
    def __init__(self, name_topic, port_topic, templates):
        self.name_topic = name_topic
        self.port_topic = port_topic
        self.templates = {frozenset([kv for kv in t_key.split('&')]): templates[t_key]
                          for t_key in sorted(templates.keys())}

    def find_port(self, desc):
        desc_key = frozenset([f'{k}={v}' for k, v in desc.items()])
        for t_key, t_body in self.templates.items():
            match = True
            for k in t_key:
                if k not in desc_key and not (k.endswith('=None') and k[:-5] not in desc):
                    match = False
            if match:
                return t_body
        return None


class Device(object):
    class Port(object):
        def __init__(self, port_description, mutable=(), constant=()):
            self.port_description = port_description
            self.mutable = mutable
            self.constant = constant
            self.subscribe = []

    def _make_port_topics(self, topic_prefix, parameters, keywords):
        if topic_prefix is None:
            topic_prefix = parameters.get('port_topic')
            if topic_prefix is None:
                self.logger.error(f'Can\'t make port_topic for port with existent template with keywords {keywords}')
                return None, [], []
        topic_prefix = topic_prefix.format(**keywords)

        result_mutable = []
        result_const = []
        for k, v in parameters.items():
            if k == 'port_topic':
                continue
            if '{port_topic}' not in k:
                k_topic = f'{topic_prefix}/{k}'
            else:
                k_topic = k.format(port_topic=topic_prefix, mqtt_key=k, **keywords)
            if isinstance(v, dict):
                _, r_m, r_c = self._make_port_topics(k_topic, v, keywords)
                result_mutable.extend(r_m)
                result_const.extend(r_c)
            else:
                if type(v) is str and '{value}' in v:
                    result_mutable.append((k_topic, v.replace('{port_topic}', topic_prefix)))
                else:
                    result_const.append((k_topic, v.replace('{port_topic}', topic_prefix)))
        return topic_prefix, result_mutable, result_const

    def __init__(self, loop, logger, device_id, ports, mqtt_templates):
        self.loop = loop
        self.logger = logger

        self.device_id = device_id
        self.name_topic = mqtt_templates.name_topic.format(device_id=device_id) if mqtt_templates.name_topic else None
        self.ports = {}
        for port_id, port_desc in ports.items():
            template = mqtt_templates.find_port(port_desc)
            if template is not None:
                port_prefix, r_mutable, r_const = \
                    self._make_port_topics(mqtt_templates.port_topic, template,
                                           {'device_id': device_id, 'port_id': port_id, **port_desc})
                if port_prefix is not None:
                    cur_port = Device.Port(port_desc)
                    cur_port.mutable = r_mutable
                    cur_port.constant = r_const
                    cur_port.subscribe = [port_prefix + '/on'] if r_mutable else ()
                    self.ports[port_id] = cur_port
            else:
                if port_desc.get('type', '') != 'NC':
                    self.logger.debug(f'No templates for port {port_id} on device {device_id} with description {port_desc}')


class Platform(object):
    def __init__(self, loop, logger, config, on_state_changed):
        self.loop = loop
        self.logger = logger

        self.subscribe_topic_to_device_port = {}
        self.notify_topic = config.get('notify_topic', None)
        self.templates = Templates(config.get('name_topic'), config.get('port_topic'), config.get('templates', {}))
        self.devices = {}
        self.client = MQTTConnector(loop, logger, config, self.on_mqtt_connect, self.on_mqtt_message)

        self.on_state_changed = on_state_changed

    async def start(self):
        await self.client.start()

    async def stop(self):
        await self.client.stop()

    async def on_mqtt_connect(self):
        for dev_id, dev in self.devices.items():
            await self.publish_device(dev_id, None)

    async def on_mqtt_message(self, topic, payload):
        try:
            if topic in self.subscribe_topic_to_device_port:
                device_id, port_id = self.subscribe_topic_to_device_port[topic]
                self.logger.debug(f'MQTT inbound message for {device_id} with parameters {port_id} and payload {payload.decode("utf-8")}')
                if self.on_state_changed:
                    await self.on_state_changed(device_id, port_id, payload.decode('utf-8'))
        except Exception as e:
            self.logger.exception(f'Exception on MQTT message processing. Exception type: {type(e)} message: {e}')

    async def publish_device(self, device_id, ports):
        if ports is None:
            cur_dev = self.devices[device_id]
        else:
            cur_dev = Device(self.loop, self.logger, device_id, ports, self.templates)
            self.devices[device_id] = cur_dev

        self.logger.debug(f'MQTT publish device {device_id}')

        if cur_dev.name_topic:
            await self.client.async_publish(cur_dev.name_topic, cur_dev.device_id, 0, True)
        for port_id, cur_port in cur_dev.ports.items():
            v_keyword = {'device_id': device_id, 'port_id': port_id, **cur_port.port_description}
            self.logger.debug(f'    Port {port_id}, {cur_port.port_description}')
            for t, v in cur_port.constant:
                try:
                    v_parsed = v.format(port_topic=t, **v_keyword) if type(v) is str else str(v)
                    await self.client.async_publish(t, v_parsed, 0, True)
                    self.logger.debug(f'        publish as constant {t}: {v_parsed}')
                except KeyError as e:
                    self.logger.warning(f'         publish as constant {t} has unknown key {e} in value template {v}')
            for t, v in cur_port.mutable:
                try:
                    v_parsed = v.format(port_topic=t, **v_keyword) if type(v) is str else str(v)
                    await self.client.async_publish(t, v_parsed, 0, True)
                    self.logger.debug(f'        publish as mutable  {t}: {v_parsed}')
                except KeyError as e:
                    self.logger.warning(f'         publish as mutable  {t} has unknown key {e} in value template {v}')
            for t in cur_port.subscribe:
                await self.client.async_subscribe(t)
                self.subscribe_topic_to_device_port[t] = (device_id, port_id)
                self.logger.debug(f'        subscribe on {t}')

    async def send_message(self, device_id, port, value):
        v_keyword = {'device_id': device_id, 'port': port, 'value': value}
        if device_id in self.devices and port in self.devices[device_id].ports:
            for t, v in self.devices[device_id].ports[port].mutable:
                v_parsed = v.format(**v_keyword)
                self.logger.debug(f'MQTT outbound message for topic {t} => {v_parsed}')
                await self.client.async_publish(t, v_parsed, 0, True)
        else:
            self.logger.debug(f'MQTT skip outbound message. No port {port} at device {device_id}')
