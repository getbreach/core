# breach-exit — exit-контейнер туннеля

Один Docker-образ, терминирующий exit туннеля Breach. `breach-server`
расшифровывает relay-стримы TURN в обычный UDP и отдаёт внутреннему серверу —
**WireGuard**, **Hysteria2** или **SOCKS5** — который выпускает трафик в интернет.

```
TURN-релей --udp/48000--> [breach-server] --> wireguard-go / sing-box(hy2) / qtun(socks5) --> интернет
```

Внутренние серверы **вшиты в образ**, независимо от ядра хоста:

- **WireGuard** — userspace `wireguard-go` (полноценный responder; sing-box для
  этого не годится — его wireguard-endpoint только инициатор). Использует
  настоящий `tun`, поэтому WG-режиму нужны `--cap-add NET_ADMIN --device
  /dev/net/tun --sysctl net.ipv4.ip_forward=1`.
- **Hysteria2** — sing-box (`hysteria2` inbound). Без caps, выпуск через `direct`.
- **SOCKS5 (stream-режим)** — breach-server сам терминирует QUIC (`breach/qtun`)
  и ходит наружу; клиенту не нужны ни WireGuard, ни tun, ни root. Без caps.

Образ **готовый и опубликован** — сервер ничего не компилирует:

```
ghcr.io/getbreach/breach-exit:latest      # linux/amd64 + linux/arm64
```

## Установка на чистый VPS

```bash
scp breach/deploy/install.sh root@vps:
ssh root@vps sh install.sh
```

Скрипт ставит Docker (если нет), тянет образ, пишет compose-стек в `/opt/breach`,
открывает `udp/48000`, запускает exit и печатает блок конфига первого клиента.
Настройка через env:

```bash
sudo PROTO=hy2 RELAY_PORT=48000 HY2_SNI=www.bing.com CLIENT=phoneA sh install.sh
```

Русское пошаговое руководство по compose — [`../../docs/deploy-ru.md`](../../docs/deploy-ru.md).

## Руками — docker run

Один контейнер обслуживает **несколько протоколов на одном UDP-порту**
(breach-server разбирает первый пакет клиента и направляет его нужному бэкенду) и
**много пользователей**. Состояние (ключи, пиры, Hy2-юзеры, серт) — в volume,
переживает рестарты и апгрейды.

```bash
docker run -d --name breach-exit --restart unless-stopped --init \
  --cap-add NET_ADMIN --device /dev/net/tun --sysctl net.ipv4.ip_forward=1 \
  -p 48000:48000/udp \
  -v breach-data:/etc/breach \
  -e PROTO=both -e HY2_SNI=www.bing.com \
  ghcr.io/getbreach/breach-exit:latest
```

`PROTO` — это **список**: `both` = `wg,hy2`, `all` = все три, можно `hy2,socks`
и т.д. Caps/sysctl нужны только когда в списке есть `wg`; без него контейнер
работает без привилегий (`install.sh` сам применяет capless-overlay).

## Апгрейд

```bash
cd /opt/breach && docker compose pull && docker compose up -d
```

Ключи, пиры, Hy2-юзеры и серт в volume — клиенты продолжают работать после
апгрейда.

## Пользователи (мультиклиент)

Каждому юзеру — своя WireGuard-пара + `10.9.0.x` и свой Hy2-пароль. Регистрация
на лету (WG-пиры горячие, Hy2 перезагружается, без рестарта контейнера):

```bash
docker exec breach-exit provision-client phoneA
```

```
===BREACH-CLIENT-CONFIG-BEGIN===
{"name":"phoneA","server":"203.0.113.7:48000","wireguard":{...},"hysteria2":{...}}
===BREACH-CLIENT-CONFIG-END===
```

Блок ложится на один `ServerConfig` в приложении (заполнены и `wireguard.*`, и
`hysteria2.*`; при `socks` добавляется `socks5.*` с токеном и пином серта). Поля
аккаунта мессенджера приложение подставляет своё.

## Env-переменные

Env только **засевают** свежий `/etc/breach`; после того как том заполнен, они
игнорируются (том — источник истины).

| Переменная | По умолчанию | Смысл |
|---|---|---|
| `PROTO` | `both` | список из `wg` / `hy2` / `socks` (`both`=`wg,hy2`, `all`=все) |
| `RELAY_LISTEN` | `:48000` | публичный UDP, куда доставляет TURN-релей |
| `PUBLIC_ENDPOINT` | автодетект | `ip:port`, объявляемый клиентам |
| `KEEPALIVE_MS` | `50` | keepalive breach-server на стрим |
| `HY2_SNI` / `HY2_PASSWORD` | `www.bing.com` / — | SNI серта / засев Hy2-юзера |

## Файрвол

Открыть входящий **udp/48000** на VPS (и в панели провайдера). Больше ничего —
выход обычный исходящий.

## Важные моменты

- WG-режим **требует** `NET_ADMIN` + `/dev/net/tun` + `ip_forward=1`; без этого
  трафик не выйдет. Hy2 и socks — без привилегий.
- В режиме `both` держи Hy2-**obfs выключенным** — обфускация прячет QUIC-заголовок,
  по которому диспетчер разводит бэкенды. Нужен obfs — подними Hy2-only на своём порту.
- SOCKS5 несёт только приложения, которые в него умеют. UDP (DNS, HTTP/3) идёт
  через UDP ASSOCIATE, но payload крупнее ~7 КБ дропается (см. `maxFragments` в
  `breach/qtun`).
- Реальный потолок пропускной — не userspace-WG, а TURN-троттл (~M×N×2.5 Мбит/с)
  и аккаунт/IP-лимит мессенджера.
