# Развёртывание breach

```
[WG-клиент]              [breach-client]           TURN-релей         [breach-server]        [WG-сервер]
 в РФ         127.0.0.1:51821  (минт кредов,                          VPS :48000  127.0.0.1:51820  на VPS
 wg0 ──────────────────> пул аллокаций)  ──relay──────────────────> (обычный UDP) ───────────────> wg0
   Endpoint=127.0.0.1:51821                                          (аккаунт мессенджера не нужен)
```

Проще всего поднять сервер готовым контейнером — см. [`deploy/README.md`](deploy/README.md)
и (по-русски) [`../docs/deploy-ru.md`](../docs/deploy-ru.md). Ниже — ручная
обвязка WireGuard, чтобы понимать, что происходит.

## Аккаунты

- **Клиент:** один аккаунт мессенджера. Для **MAX** — токен + профиль спуфинга в
  `config.json` (`mintMode: "silent"` никого не будит; `"call"` звонит на
  `calleeId` — тогда заведи свой второй аккаунт). Для **WB** — сессия WB ID и
  личный чат (минт тихий, собеседник ничего не получает).
- **Сервер:** аккаунт мессенджера не нужен.

## 1. Сервер (VPS за рубежом)

WireGuard-сервер `wg0` (слушает udp/51820), один пир — клиент:

```ini
# /etc/wireguard/wg0.conf  (сервер)
[Interface]
Address = 10.9.0.1/24
ListenPort = 51820
PrivateKey = <SERVER_PRIV>

[Peer]                       # клиент
PublicKey = <CLIENT_PUB>
AllowedIPs = 10.9.0.2/32
```

```bash
wg-quick up wg0
# NAT, чтобы трафик клиента уходил в интернет:
sysctl -w net.ipv4.ip_forward=1
iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE

./breach-server -listen :48000 -wg 127.0.0.1:51820
```

Открой входящий **udp/48000** на файрволе VPS (сюда доставляет TURN-релей).

## 2. Клиент (устройство в РФ)

WireGuard-клиент целится в breach-client, **не** в VPS:

```ini
# конфиг wg-клиента
[Interface]
Address = 10.9.0.2/24
PrivateKey = <CLIENT_PRIV>
MTU = 1280                       # запас под ChannelData/relay

[Peer]
PublicKey = <SERVER_PUB>
Endpoint = 127.0.0.1:51821       # <-- breach-client, локальный вход туннеля
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 15
```

```bash
# MAX
./breach-client -config config.json -server <VPS_IP>:48000 \
    -wg-listen 127.0.0.1:51821 -streams 4 -mints 1
# WB
./breach-client -provider wb -wb-session wb.json -wb-chat 'chats/<id>' \
    -server <VPS_IP>:48000 -wg-listen 127.0.0.1:51821 -streams 4

wg-quick up wg-client
```

### ВАЖНО: петля маршрутизации

WG-клиент заворачивает `0.0.0.0/0` в туннель, но собственный трафик breach-client
к TURN-релею и к API минта должен уходить через **физический** интерфейс — иначе
он зациклится в туннеле и всё встанет. Прибей эти маршруты к реальному шлюзу:

```bash
GW=$(ip route show default | awk '/default/{print $3; exit}')
DEV=$(ip route show default | awk '/default/{print $5; exit}')
# TURN-рёбра провайдера: MAX — 155.212.0.0/16, WB — 176.101.92.0/24
ip route add 155.212.0.0/16 via $GW dev $DEV
ip route add <VPS_IP>/32 via $GW dev $DEV     # если сервер за интернетом
# плюс /32 к API-хосту минта (api2.oneme.ru для MAX)
```

(Запускать после `wg-quick up`, либо положить в `PostUp`/`PostDown`.)

## Stream-режим (без WireGuard и root)

Вместо WG клиент может поднять локальный SOCKS5, а exit будет ходить наружу сам
(QUIC поверх релея). Ни tun, ни root не нужны, петли маршрутизации нет:

```bash
# сервер
./breach-server -listen :48000 -socks 127.0.0.1:1 -clients /etc/breach/clients
# клиент
./breach-client -provider wb -wb-session wb.json -wb-chat 'chats/<id>' \
    -server <VPS_IP>:48000 -socks 127.0.0.1:1080 \
    -socks-token <пароль> -socks-pin <sha256 серта exit'а>
```

## Тюнинг

- `-streams N` — аллокаций на кред (~2.5 Мбит/с каждая), `-mints M` — кредов
  (для MAX `"call"` каждый минт звонит; для `silent`/WB — нет). Пропускная
  ≈ M × N × ~2.5 Мбит/с, но реальный потолок — аккаунт/IP-троттл: не долби один
  аккаунт. Начни с `-streams 4 -mints 1`.
- `-keepalive-ms` (по умолчанию 50) — ниже = больше обратного трафика = троттл
  держится открытым под более асимметричной нагрузкой, ценой небольшого оверхеда.
