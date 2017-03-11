# megad-mqtt-gw

Приложение является гейтом между мегами MQTT. 
На данный момент на мегах поддерживаются входы (In) и выходу (Out).
Остальные буду добавлять по мере потребности/поступления заявок.

Другими словами оно предназначено для связывания устройств MegaD с
очередью MQTT.

Может быть полезно при организации сервера автоматизации на базе
[home-assistant](https://home-assistant.io/) или
[WirenBoard](http://contactless.ru/controllers/).


## Логика работы

При получении сообщения от меги:
  - опубликовать его в MQTT
  - вернуть меге комманду, определяемую в конфигурационном файле:
     - комманду, настроенную на ней самой (параметр
       "response_mode"="device", значение по умолчанию)
     - пустую комманду (параметр "response_mode"="empty")
  - перечитать состояния портов и для изменившихся опубликовать
    сообщения в MQTT

При получении сообщения от MQTT:
  - передать его меге
  - перечитать состояния портов и для изменившихся
      опубликовать сообщения в MQTT


Вариант с возвратом в мегу команды настроенной на самой меге
используется в случае если используются простые команды и вы хотите,
что бы проведение мег не сильно отличалось при наличии/отсутствии
сервера.

Вариант с возвратом пустой команды приводит к тому, что мега не
выполняет ничего при нажатии кнопки и комманду, например, зажечь
лампочку, должен отдать сервер. Соотвественно он должен быть рабочим и
доступным 24х7.


## Установка

  - sudo pip install git+https://github.com/repalov/megad-mqtt-gw/
  - Отредактировать /etc/megad-mqtt-gw.conf
  - sudo systemctl daemon-reload
  - sudo systemctl enable megad-mqtt-gw
  - sudo systemctl start megad-mqtt-gw
  - sudo systemctl status megad-mqtt-gw


## Пример конфигурации

Для связывания с home-assistant или WirenBoard использую следующую конфигурацию.
```json
{
  "devices": [
    { "address": "192.168.1.14", "password": "sec" },
    { "address": "192.168.1.15", "password": "sec" },
    { "address": "192.168.1.16", "password": "sec" }
  ],
  "mqtt": {
    "address": "192.168.1.38",
    "prefix": "/devices/megad/controls/",
    "device_name_topic": "/devices/{device_id}/meta/name",
    "device_port_topic": "/devices/{device_id}/controls/{port}",
    "template": {
      "0"  : { "value": "{value}", "meta": { "name": "{name}", "order": "{pn}", "type": "switch", "readonly": 1 } },
      "1"  : { "value": "{value}", "meta": { "name": "{name}", "order": "{pn}",  "type": "switch" } },
      "1/1": { "value": "{value}", "meta": { "name": "{name}", "order": "{pn}",  "type": "range", "max": 255 } }
    }
  },
  "http": {
    "address": "0.0.0.0",
    "port": 19780
  }
}
```


## Пример конфигурации для home-assistant

Пример описания диммируемого и недиммируемого каналов:

```yaml
light:
  - platform: mqtt
    name: "Недиммируемый канал"
    command_topic: "/devices/megad_192.168.1.114/controls/p7/on"
    state_topic: "/devices/megad_192.168.1.114/controls/p7/value"
    payload_on: "1"
    payload_off: "0"
    optimistic: false
  - platform: mqtt_template
    name: "Диммируемый канал"
    command_topic: "/devices/megad_192.168.1.114/controls/p10/on"
    state_topic: "/devices/megad_192.168.1.114/controls/p10/value"
    command_on_template: "{%- if brightness is defined -%}{{ brightness | d }}{%- else -%}255{%- endif -%}"
    command_off_template: "0"
    state_template: "{%- if value| float > 0 -%}on{%- else -%}off{%- endif -%}"  # must return `on` or `off`
    brightness_template: "{{ value }}"
```


## Параметры командной строки

  - **--config <имя файла>** - Имя конфигурационного файла. Значение по умолчанию */etc/megad-mqtt-gw.conf*
  - **--log <имя файла>** - имя журнального файла. Значение по умолчанию */var/log/megad-mqtt-gw.log*
  - **--debug** - включает отладочный режим. В журнал и на консоль выводится расширенная информация.


## Ручная установка

### Установка зависимостей
  - sudo pip install aiohttp
  - sudo pip install lxml
  - sudo pip install paho-mqtt

### Получение исходников
  git clone https://github.com/repalov/megad-mqtt-gw.git
  cd megad-mqtt-gw

### Установка исполнимого файла
  sudo cp megad-mqtt-gw.py /usr/bin

### Установка конфигурационного файла
  - sudo cp megad-mqtt-gw.conf /etc
  - Отредактировать  /etc/megad-mqtt-gw.conf

### Автозапуск с помощью systemd
  - sudo cp megad-mqtt-gw.service /lib/systemd/system/
  - Исправить в */lib/systemd/system/megad-mqtt-gw.service* все пути
    на верные и абсолютные.
  - Включить автозапуск: ```sudo systemctl enable megad-mqtt-gw.service```
  - Запустить: ```sudo systemctl start megad-mqtt-gw.service```
  - Проверить состояние: ```sudo systemctl status megad-mqtt-gw.service```
