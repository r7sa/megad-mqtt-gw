# megad-mqtt-gw

Приложение является гейтом между мегами MQTT.

Другими словами оно предназначено для связывания устройств MegaD с
очередью MQTT.

Может быть полезно при организации сервера автоматизации на
базе home-assistant или WirenBoard.

Логика работы на данный момент такова:
 - при получении сообщения от меги:
    - опубликовать его в MQTT
    - вернуть меге комманду, настроенную на ней самой *)
    - перечитать состояния портов и для изменившихся
      опубликовать сообщения в MQTT
 - при получении сообщения от MQTT:
    - передать его меге
    - перечитать состояния портов и для изменившихся
      опубликовать сообщения в MQTT


*) Настроенные команды считываются только при старте, потом не обновляются.
Данная логика реализованна специально, что бы поведение мег не сильно
различалось при наличии/отсутствии сервера.


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

На данный момент не до конца разобрался с диммированием, поэтому
все каналы используются в режиме вкл/выкл.

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
