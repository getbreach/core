# Свой сервер на docker compose

Поднимаем exit Breach руками. Собирать ничего не надо, образ уже готовый, его
просто запускаем.

Что нужно: VPS не в России (иначе смысла ноль, выход должен быть
незаблокированным) и root по ssh. Железо подойдёт самое дешёвое, хватит одного
ядра и 512 мб. Образ весит около 22 мб.

## Докер

Если ещё не стоит:

```bash
curl -fsSL https://get.docker.com | sh
```

## Compose-файл

Делаем папку и открываем файл:

```bash
mkdir -p /opt/breach && cd /opt/breach
nano docker-compose.yml
```

Протокол берём Hysteria2. Он не только проще (не нужен tun и лишние права), но
и быстрее там, где это реально заметно: при скачивании одним потоком. WireGuard
в одном потоке ощутимо проседает.

Причина простая. Внутри WireGuard едет обычный TCP, а он плохо переносит
джиттер и переупорядочивание пакетов. Наш путь через TURN всё это добавляет, и
окно TCP постоянно схлопывается. У Hysteria2 свой контроль перегрузки поверх
QUIC, ему такое не мешает. В многопоточной качалке разница почти пропадает, но
обычно файл тянется как раз в один поток.

Итого:

```yaml
services:
  breach-exit:
    image: ghcr.io/getbreach/breach-exit:latest
    container_name: breach-exit
    restart: unless-stopped
    init: true
    ports:
      - "48000:48000/udp"
    volumes:
      - breach-data:/etc/breach
    environment:
      PROTO: hy2
      RELAY_LISTEN: ":48000"
      PUBLIC_ENDPOINT: "1.2.3.4:48000"    # сюда свой IP
      HY2_SNI: www.bing.com

volumes:
  breach-data:
```

Обязательно поменять надо только `PUBLIC_ENDPOINT`. Это адрес, который получат
клиенты. Если оставить пустым, сервер попробует узнать свой IP через
api.ipify.org, но за NAT или на машине с несколькими адресами ошибётся.

Порт можно поставить любой. Тогда правим его в трёх местах: `ports`,
`RELAY_LISTEN` и `PUBLIC_ENDPOINT`.

В volume `breach-data` лежат ключи сервера, список клиентов и сертификат Hy2.
Он переживает перезапуск и обновление образа, так что старые конфиги после
апдейта работают дальше.

## Если нужен ещё и WireGuard

Обычно нужен для совместимости, когда хочется иметь оба варианта. Как основной
протокол не советую, скорость в один поток будет ниже.

Ставим `PROTO: both` и добавляем права, потому что wireguard-go нужен tun и
включённый форвардинг:

```yaml
    environment:
      PROTO: both
      # остальное как выше
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      net.ipv4.ip_forward: "1"
```

На дешёвых OpenVZ и LXC `/dev/net/tun` часто нет вообще, тогда контейнер упадёт
с `Unable to modify interface`. Просто возвращаемся на `PROTO: hy2`, там и
скорость выше.

Кстати, оба протокола висят на одном UDP-порту. Сервер смотрит первый пакет
клиента и сам понимает, куда его отдать.

## Запуск

```bash
docker compose up -d
docker logs -f breach-exit
```

Если в логах появилось
`breach-exit: PROTO=hy2 relay=:48000 endpoint=1.2.3.4:48000`, значит поднялось.

## Порт

В самой системе порт откроется сам, а вот в панели провайдера (Timeweb,
Hetzner, DigitalOcean, Vultr) его надо открыть руками. Нужен UDP 48000.

Если стоит ufw, то ещё:

```bash
ufw allow 48000/udp
```

Когда «поставил, а не подключается» — почти всегда дело именно в этом порте.
Проверить со своей машины:

```bash
nc -zvu 1.2.3.4 48000
```

## Клиенты

```bash
docker exec breach-exit provision-client phoneA
```

Выдаст блок, его вставляем в приложение:

```
===BREACH-CLIENT-CONFIG-BEGIN===
{"name":"phoneA","server":"1.2.3.4:48000","wireguard":null,"hysteria2":{...}}
===BREACH-CLIENT-CONFIG-END===
```

На каждое устройство лучше заводить своего клиента, у каждого будет свой пароль
и свой IP. В имени можно латиницу, цифры, `_` и `-`, до 32 символов.

Остальное:

```bash
docker exec breach-exit list-clients          # кто заведён
docker exec breach-exit remove-client phoneA  # отозвать
docker exec breach-exit stats                 # трафик и нагрузка
```

## Обновление

```bash
cd /opt/breach
docker compose pull && docker compose up -d
```

Остановить: `docker compose down`.

А вот `docker compose down -v` снесёт volume вместе с ключами и клиентами.
После него все выданные конфиги станут нерабочими, так что `-v` только если
правда хотим начать заново.
