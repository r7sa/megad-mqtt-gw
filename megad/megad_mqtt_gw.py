#!/usr/bin/env python3
import argparse
import asyncio
import json
import logging
import logging.handlers
import signal
import sys
import megad.megad
import megad.mqtt


class StdStreamLogger(object):
    def __init__(self, logger, level):
        self.logger = logger
        self.level = level

    def write(self, message):
        if message.rstrip() != '':
            self.logger.log(self.level, message.rstrip())

    def flush(self):
        pass


class Main:
    def __init__(self):
        parser = argparse.ArgumentParser(description='MQTT (HomeAssistant, WirenBoard, etc.) driver for MegaDevices (ab-log.ru).')
        parser.add_argument('--config', default='/etc/megad-mqtt-gw.conf', help='name of configuration file')
        parser.add_argument('--log', default='/var/log/megad-mqtt-gw.log', help='name of log file')
        parser.add_argument('--debug', action='store_true', default=False, help='output more information to log and console')
        args = parser.parse_args()

        try:
            self.config = json.load(open(args.config, 'rt', encoding='utf-8'))
        except Exception as e:
            raise RuntimeError(f'Can\'t load configuration from path "{args.config}". Exception type: {type(e)} message: {e}')

        try:
            self.logger = logging.getLogger(__name__)
            self.logger.setLevel(logging.DEBUG if args.debug else logging.INFO)
            handler = logging.handlers.TimedRotatingFileHandler(args.log, when='midnight', backupCount=3)
            formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s')
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            if args.debug:
                handler_console = logging.StreamHandler(sys.stdout)
                handler_console.setFormatter(formatter)
                self.logger.addHandler(handler_console)
            sys.stdout = StdStreamLogger(self.logger, logging.INFO)
            sys.stderr = StdStreamLogger(self.logger, logging.ERROR)

            self.logger.info('------------- MegaD-MQTT gateway started -------------------')
        except Exception as e:
            raise RuntimeError(f'Can\'t initialize logging with path "{args.log}". Exception type: {type(e)} message: {e}')

        self.loop = asyncio.get_event_loop()

        try:
            self.logger.info('Creating platforms')
            self.megad = megad.megad.Platform(self.loop, self.logger, self.config.get('megad', {}),
                                              self.on_megad_new_device, self.on_megad_lost_device,
                                              self.on_megad_message)
            self.mqtt = megad.mqtt.Platform(self.loop, self.logger, self.config.get('mqtt', {}),
                                            self.on_mqtt_message)
        except Exception as e:
            self.logger.exception(f'Error at creating platforms. Exception type: {type(e)} message: {e}')
            raise RuntimeError(f'Error at creating platforms. Exception type: {type(e)} message: {e}')

    async def start(self):
        await self.mqtt.start()
        await self.megad.start()

    async def stop(self):
        await self.megad.stop()
        await self.mqtt.stop()

    def signal_exit(self):
        self.loop.stop()

    async def on_megad_new_device(self, device_id):
        await self.mqtt.publish_device(device_id, self.megad.devices.devices[device_id].ports)

    async def on_megad_lost_device(self, device_id):
        pass

    async def on_megad_message(self, device_id, port, value):
        await self.mqtt.send_message(device_id, port, value)

    async def on_mqtt_message(self, device_id, port, value):
        await self.megad.send_message(device_id, port, value)

    def run(self):
        try:
            self.logger.info('Starting platforms')
            task = self.loop.create_task(self.start())
            self.loop.run_until_complete(task)
            task.result()
        except Exception as e:
            self.loop.close()
            self.logger.exception(f'Error at startup. Exception type: {type(e)} message: {e}')
            raise RuntimeError(f'Error at startup. Exception type: {type(e)} message: {e}')

        for signame in ('SIGINT', 'SIGTERM'):
            self.loop.add_signal_handler(getattr(signal, signame), self.signal_exit)

        self.loop.run_forever()

        try:
            self.logger.info('Stopping platforms')
            task = self.loop.create_task(self.stop())
            self.loop.run_until_complete(task)
            task.result()
        except Exception as e:
            self.loop.close()
            self.logger.exception(f'Error at stoping. Exception type: {type(e)} message: {e}')
            raise RuntimeError(f'Error at stoping. Exception type: {type(e)} message: {e}')

        self.logger.info('Application finished.')


if __name__ == '__main__':
    try:
        Main().run()
    except Exception as e:
        print(f'{e}')
