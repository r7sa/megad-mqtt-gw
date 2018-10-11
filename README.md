[![Updates](https://pyup.io/repos/github/repalov/megad-mqtt-gw/shield.svg)](https://pyup.io/repos/github/repalov/megad-mqtt-gw/)

# megad-mqtt-gw

Приложение является гейтом между устройствами MegaD-328/2561 и очередью MQTT. 
Может быть полезно при организации сервера автоматизации на базе
[home-assistant](https://home-assistant.io/) или
[WirenBoard](http://contactless.ru/controllers/).

Поддерживаемые возможности:
  - поддерживаются входы (In) и выходу (Out), ряд сенсоров.
    Остальные буду добавлять по мере потребности/поступления заявок,
  - автообнаружение устройств с созданием соотвествующих топиков в MQTT,
  - задание создаваемых топиков посредством шаблонов, что позволяет 
    перенастраивать на взаимодействие с wirenboard и homeassistant 
    только заменой конфигурации,
  - discovery в homeassistant видит автооопределенные устройства.    


## Установка

  - sudo pip install git+https://github.com/repalov/megad-mqtt-gw/
  - Скопировать в файл /etc/megad-mqtt-gw.conf содержимое 
    /etc/megad-mqtt-gw.homeassistant.conf или /etc/megad-mqtt-gw.wirenboard.conf
  - sudo systemctl daemon-reload
  - sudo systemctl enable megad-mqtt-gw
  - sudo systemctl start megad-mqtt-gw
  - sudo systemctl status megad-mqtt-gw


## Конфигурирование

Примеры конфигурации для работы с HomeAssistant и WirenBoard устанавливаются в каталог /etc под именами
/etc/megad-mqtt-gw.homeassistant.conf и /etc/megad-mqtt-gw.wirenboard.conf соотвественно.

## Логика работы

При получении сообщения от MegaD-328/2561:
  - опубликовать его в MQTT
  - вернуть меге пустую комманду.

При получении сообщения от MQTT:
  - передать его соотвествующему устройству для соотвествующего порта,
  - запустить цикл чтения состояния портов для изменившихся опубликовать
    сообщения в MQTT. Цикл останавливается когда значение 
    целевого порта перестанет меняться.

Периодически:
  - если не запрещено, проводить автообнаружение устройств,
  - при появлении новых устройств публиковать их в MQTT в соотвествии с шаблонами, заданными в конфигурации,
  - считывать состояние портов и для изменившихся публиковать их в MQTT (pooling).  


## Пример настройки HomeAssistant

При включенном обнаружении (секция scan конфигурационного файла), конфигурация всех обнаруженных 
устройств считывается с них автоматически и публикуется в MQTT в формате, поддерживаемом модулем 
discovery из состава HomeAssistant. Поэтому специально добавлять их в конфигурацию руками нет необходимости.
Если какое то устройство не поддерживается, значит у меня его не было в наличии и не было 
возможности отладить работы с ним. Для реализации поддержки устройства можно со мной 
списаться, или сделать issue.  

При ручном добавлении устройств есть смысл пользоваться модулями поддержки MQTT. Пример описания 
диммируемого и недиммируемого каналов:

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

После того, как каналы заведены и описаны, достаточно настроить автоматизацию, что бы все заработало.


## Описание скрипта

Скрипт для запуска гененрируется pip-ом при установке и обычно ставится под именем /usr/bin/megad-mqtt-gw

Поддерживаются следующие аргументы коммандной строки:
  - **--config <имя файла>** - Имя конфигурационного файла. Значение по умолчанию */etc/megad-mqtt-gw.conf*
  - **--log <имя файла>** - имя журнального файла. Значение по умолчанию */var/log/megad-mqtt-gw.log*
  - **--debug** - включает отладочный режим. В журнал и на консоль выводится расширенная информация.

Для работы скрипта не нужны особые привелегии, за исключением прав на запись в файл журнала (log-файл).

