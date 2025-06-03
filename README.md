# SECMAN

Хранилище секретов, все возможные совпадения с Vault случайны(вольная/наивная интерпритация автора). Приложение состоит из клиентской и серверной части, в комплекте 2 бинарника. Все данные хранятся в зашифрованном виде в том числе и ключи шифрования. Для получения доступа к ключам шифрования необходимо восстановить рутовый ключ. Рутовый ключ разбит на части с использованием схемы Shamir secret sharing.

## Основные возможности
1. Регистрация новых пользователей
2. Аутентификация польователя через логин и пароль
3. Хранение секретов в формате ключ - значение
4. Хранение секретов - бинарных файлов в S3
5. Хранение данных банковских карт

[Пример использования](#пример-использования)
### Road map
- Сейчас нет никакой авторизации пользователей. Все учетки имеют одинаковые права и доступы к секретам. В дальнейшем необходиом добавить политики доступа
- Добавление тенантов и неймспейсов. Это позволит вынести секреты из одной кучи в разные логические пространства
- Добавить ротацию ключей шифрования
- Добавить observability
- Добавить ротацию секретов
- Дбавить режим HA

## Настройка DEV окружения

Генерация ключа с самоподписным сертификатом, создание конфигурационного файла и запуск базы данных. В ходе работы скрипта необходимо заполнить данные сертификата в интерактивном режиме
```bash
task init
``` 

Проверка что все сущности созданы
```bash
task check-env
```

Настроить параметры сервера и подключение к базе данных в `config.yml`. Пример корректного содержимого
```yml
log_level: -1

server:
  address: 127.0.0.1:8443
  cert_path: certs/cert.pem
  key_path: certs/private.key

storage:
  type: redis
  host: 127.0.0.1:6379
  password: ""
  db: 0
```

Подгрузка переменных окружени
```bash
source env.sh
```

Сборка клиента
```bash
task build-cli
```
Сборка сервера
```bash
task build-cli
```

## Пример использования

> Перед началом работы необходимо выполнить действия из [настроек окружения](#настройка-dev-окружения)

В отдельном терминале запустить сервер
```bash
secman_server
```

Сервер запускается в зашифрованном состоянии. В данный момент можно выполнить только два действия:
- Прочитать информацию о сервере
  ```bash
  ➜  secman git:(core) ✗ secman status
  Version:     v1.0.0
  Build date:  2025/06/04 00:18:00
  Barrier:     AES256 SSS keys: 0/3
  Initialized: false
  Sealed:      true
  ```
- Инициализировать сервер. Инциализация сервера происходит только один раз. В ответе будет находиться `Root token` его можно использовать для выполнения запросов к серверу. Для этого необходимо сохранить его в переенную окружения `ROOT_TOKEN`. Если выполнить команду с флагом `-pt`, токен будет сохранен и будет автоматически использоваться. Помимо токена в выводе будут находиться 5 ключей, для того чтбы расшифровать сервер, достаточно использовать 3 произвольных.

  ```bash
  ➜  secman git:(core) ✗ secman init -pt
  Server initialized Successfull

  Use this token to authenticate as root, it will be needed for future operations. To use it, set the ROOT_TOKEN environment variable.
  Root token: 77HKWP/EePZ1xf/rVhsGDXEw+8mDsX9ReS9pE9NP8I0=

  Use thresholds to unseal the server.
  Thresholds:
  - oBvlE3rwD5v+oiKv2KglqMPjxRiYrYnDwbEPAF1hlLGb
  - U+tu/5Vf6ueKtosnU/UwVG9eU/A1csUSLADf4SeBtk6N
  - O0TN7IsjKmXrt7rD4ehcGVCnR4hrlQ6IO4VESHDyvCir
  - A5jYo8eYWDpcxBkvtwKd74b/4jOoMwxJn2HfhH/AQs8R
  - GtmUN6Ow1LpXtqPRA4Qi7qTtkJmUPGxkQYAuajqi423h

  ```


Выполнить операцию ансила
```bash
➜  secman git:(core) ✗ secman unseal -k oBvlE3rwD5v+oiKv2KglqMPjxRiYrYnDwbEPAF1hlLGb                                            
Server sealed: true
Barrier:       AES256 SSS keys: 1/3
➜  secman git:(core) ✗ secman unseal -k U+tu/5Vf6ueKtosnU/UwVG9eU/A1csUSLADf4SeBtk6N                                            
Server sealed: true
Barrier:       AES256 SSS keys: 2/3
➜  secman git:(core) ✗ secman unseal -k O0TN7IsjKmXrt7rD4ehcGVCnR4hrlQ6IO4VESHDyvCir                                            
Server sealed: false
Barrier:       AES256 SSS keys: 3/3
```
Авторизация/аутентификации пользователя может быть выоплнена разными способами. Сейчас реализован только один - движок для работы с логином и паролем. Перед началом работы движок необходимо активировать, это делается один раз

  ```bash
  ➜  secman git:(core) ✗ secman engine enable auth/logopass                                                                  
  Successfull
  ```

Движок активирован, теперь необходимо обозначить `secman`-у что этот движок используется в качестве средства авторизации/аутентификации
  ```bash
  secman auth -enable /auth/logopass
  ```

Операция регистрации пользователя
  ```bash
  ➜  secman git:(core) ✗ secman logopass register -u ivan -p 123
  Successfull
  ```
Логин
  ```bash
  ➜  secman git:(core) ✗ secman logopass login -u ivan -p 123   
  Successfull
  ```

#### Движок KV
Движок KV позволяет хранить секреты в формате ключ значение. Для каждого секрета можно задать метаданные.
```bash
➜  secman git:(core) ✗ secman kv                        
Usage: secman kv <operation> [-k <key>] [-v <value>] -fiz=<baz>...

# активация
➜  secman git:(core) ✗ secman engine enable secrets/kv                                                                     
Successfull

# добавление секрета
➜  secman git:(core) ✗ secman kv write -h                             
Usage: secman kv <operation> [-k <key>] [-v <value>] -fiz=<baz>...
  -k string
        key
  -v string
        value

➜  secman git:(core) ✗ secman kv write -k pg/standalone/1 -v qwerty123
Successfull

# чтение секрета
➜  secman git:(core) ✗ secman kv read -h 
Usage: secman kv <operation> [-k <key>] [-v <value>] -fiz=<baz>...
  -k string
        key

➜  secman git:(core) ✗ secman kv read -k pg/standalone/1            
Successfull
value: qwerty123

# чтение metadata
➜  secman git:(core) ✗ secman kv read -k pg/standalone/1/metadata
Successfull
created_at: 2025-06-03T23:17:18+03:00

# удаление
➜  secman git:(core) ✗ secman kv delete -h                       
Usage: secman kv <operation> [-k <key>] [-v <value>] -fiz=<baz>...
  -k string
        key

➜  secman git:(core) ✗ secman kv delete -k pg/standalone/1           
Successfull
```

#### Движок Blob
Движок `Blob` используется для хранение произвольных бинарных данных. При его активации необходимо указать параметры подключения к хранилиoe `S3`

```bash
# активация
➜  secman git:(core) ✗ secman engine enable secrets/blobs s3_url=127.0.0.1:9000 s3_user=minio s3_pass=minio123 s3_ssl=false
Successfull

➜  secman git:(core) ✗ secman blob -h                                                                                           
Usage: secman blob <token> <operation> [meta <key>=<value>]

# добавление секрета, результатом работы операции станет токен. Он позволяет получить секрет в дальнейшем
➜  secman git:(core) ✗ secman blob write -h                   
Usage: secman blob <token> <operation> [meta <key>=<value>]
  -f string
        path to the file to upload

➜  secman git:(core) ✗ secman blob write -f go.sum 
Successfull
Token: yDIfZNaKjcoecMMjnf1YHS8LcUE39Y7RmfqRfpRIno3yOyNBWuPwHOjBFXFqVLq9E4T_GMtqQ234KAAFunMwuw==

# чтение секрета
➜  secman git:(core) ✗ secman blob read -h                                                                                         
Usage: secman blob <token> <operation> [meta <key>=<value>]
  -d string
        directory to save the file
  -m    show metadata

➜  secman git:(core) ✗ secman blob read -d /tmp yDIfZNaKjcoecMMjnf1YHS8LcUE39Y7RmfqRfpRIno3yOyNBWuPwHOjBFXFqVLq9E4T_GMtqQ234KAAFunMwuw==                                                              
Successfull                      
File saved to /tmp/go.sum

➜  secman git:(core) ✗ head -n 2 /tmp/go.sum
github.com/armon/go-radix v1.0.0 h1:F4z6KzEeeQIMeLFa97iZU6vupzoecKdU5TX24SNppXI=
github.com/armon/go-radix v1.0.0/go.mod h1:ufUuZ+zHj4x4TnLV4JWEpy2hxWSpsRywHrMgIH9cCH8=
# чтение metadata
➜  secman git:(core) ✗ secman blob read -m yDIfZNaKjcoecMMjnf1YHS8LcUE39Y7RmfqRfpRIno3yOyNBWuPwHOjBFXFqVLq9E4T_GMtqQ234KAAFunMwuw==
Successfull
file_name: go.sum
created_at: 2025-06-03T23:24:04.405766+03:00

# добавление matadata
➜  secman git:(core) ✗ secman blob update -h                                                                                              
Usage: secman blob <token> <operation> [meta <key>=<value>]
➜  secman git:(core) ✗ secman blob update yDIfZNaKjcoecMMjnf1YHS8LcUE39Y7RmfqRfpRIno3yOyNBWuPwHOjBFXFqVLq9E4T_GMtqQ234KAAFunMwuw== fiz=baz
Successfull

➜  secman git:(core) ✗ secman blob read -m yDIfZNaKjcoecMMjnf1YHS8LcUE39Y7RmfqRfpRIno3yOyNBWuPwHOjBFXFqVLq9E4T_GMtqQ234KAAFunMwuw==
Successfull
created_at: 2025-06-03T23:24:04.405766+03:00
file_name: go.sum
fiz: baz

# удаление
➜  secman git:(core) ✗ secman blob delete yDIfZNaKjcoecMMjnf1YHS8LcUE39Y7RmfqRfpRIno3yOyNBWuPwHOjBFXFqVLq9E4T_GMtqQ234KAAFunMwuw==  
Successfull
```
#### Движок PCI_DSS
Движок PCI_DSS позволяет безопасно хранить данные банковских карт. Пользователь передает данные карты, в замен получает токены для каждого атрибута. Дрступ к атрибутам осуществляется через токены полученные при создании

```bash
# активация
➜  secman git:(core) ✗ secman engine enable secrets/pci_dss                                                                               
Successfull

# добавление секрета
➜  secman git:(core) ✗ secman pci_dss write -h                                                                       
Usage: secman pci_dss <operation> [-p <pan>] [-cn <cardholderName>] [-ed <expiryDate>] [-sc <securityCode>] [-pt <panToken>] [-cct <cardholderNameToken>] [-edt <expiryDateToken>] [-sc <securityCodeToken>]
  -cn string
        Cardholder Name
  -ed string
        Expiry Date
  -p string
        PAN 
  -sc string
        Security Code

➜  secman git:(core) ✗ secman pci_dss write -p 1234567890123454 -cn "Ivan Lapshin" -ed "2025-01-01T00:00:00Z" -sc 123
Successfull
PAN token:             da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754
Cardholder Name token: X5gJJUuA24zb0JM8suv_a7KlRPyBE1k7EIXNDOXeSmLyw6Lm7rYnlomJulUvmYA9ztQCCsF+baj1m4BDVEfqKA==
Expiry Date token:     ETbWPEMc+yw+96RKBX0U9MNKvpz3ZNN9VZfXiP8y1OJsttorDvHMSssZKMsf42xWkXiMtxnY_LDm02TDRSvpxQ==
Security Code token:   zo7zPDkpNZoETbFi8TV_p_16cDjacbYKXxc9p7AD8JEXpW7MwLPsRblUU6f1V7bR4MJsXPPwGIb8HDaDbZbDyg==

# чтение PAN
➜  secman git:(core) ✗ secman pci_dss read -h                                                                                                                                                                
Usage: secman pci_dss <operation> [-p <pan>] [-cn <cardholderName>] [-ed <expiryDate>] [-sc <securityCode>] [-pt <panToken>] [-cct <cardholderNameToken>] [-edt <expiryDateToken>] [-sc <securityCodeToken>]
  -cct string
        Cardholder Name Token
  -edt string
        Expiry Date Token
  -m    Show Metadata
  -pt string
        PAN Token
  -sc string
        Security Code Token

➜  secman git:(core) ✗ secman pci_dss read -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754                                                                   
Successfull
value: 1234567890123454

# чтение metadata
➜  secman git:(core) ✗ secman pci_dss read -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754 -m
Successfull
created_at: 2025-06-03T23:34:33+03:00

# добавление matadata
➜  secman git:(core) ✗ secman pci_dss update -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754 fiz=baz
Successfull

➜  secman git:(core) ✗ secman pci_dss read -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754 -m
Successfull
created_at: 2025-06-03T23:34:33+03:00
fiz: baz

# чтение Cardholder
➜  secman git:(core) ✗ secman pci_dss read -cct X5gJJUuA24zb0JM8suv_a7KlRPyBE1k7EIXNDOXeSmLyw6Lm7rYnlomJulUvmYA9ztQCCsF+baj1m4BDVEfqKA== -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754
Successfull
value: Ivan Lapshin

# чтение Expiry
➜  secman git:(core) ✗ secman pci_dss read -edt ETbWPEMc+yw+96RKBX0U9MNKvpz3ZNN9VZfXiP8y1OJsttorDvHMSssZKMsf42xWkXiMtxnY_LDm02TDRSvpxQ== -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754
Successfull
value: 25/01

# чтение Security
➜  secman git:(core) ✗ secman pci_dss read -sc zo7zPDkpNZoETbFi8TV_p_16cDjacbYKXxc9p7AD8JEXpW7MwLPsRblUU6f1V7bR4MJsXPPwGIb8HDaDbZbDyg== -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754
Successfull
value: 123

# удаление
➜  secman git:(core) ✗ secman pci_dss delete -h                                                                                                                                                             
Usage: secman pci_dss <operation> [-p <pan>] [-cn <cardholderName>] [-ed <expiryDate>] [-sc <securityCode>] [-pt <panToken>] [-cct <cardholderNameToken>] [-edt <expiryDateToken>] [-sc <securityCodeToken>]
  -pt string
        PAN Token

➜  secman git:(core) ✗ secman pci_dss delete -pt da6e52dd623612040283f90c5df7bada907a0527bda5520a61dbe0902ce1c754                                                                
Successfull
```