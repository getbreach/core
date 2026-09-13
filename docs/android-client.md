# Встраивание Breach в Android-приложение

Go-ядро поставляется как `gomobile`-биндинг (`.aar`), которым управляют из Kotlin
внутри `VpnService`.

> Этот документ — про **транспорт Breach**. Внутренний протокол (Hysteria2 /
> WireGuard), tun и маршрутизацию держит **sing-box (libbox)** — отдельный
> `.aar`. Breach только relay'ит UDP через TURN; sing-box подключается к
> локальному «рту» Breach. В stream-режиме внутренний протокол не нужен вовсе —
> exit ходит наружу сам, а приложение открывает локальный SOCKS5.

## Архитектура

```
tun ──► sing-box / libbox ──► транспорт Breach (.aar) ──► TURN-релей ──► exit (VPS)
        (Hy2/WG-клиент,        (рот 127.0.0.1:51821
         tun, маршруты, DNS)     → TURN → exit)
```

## Ядро

```go
func StartTransport(configJSON string, p Protector, l Logger) (*Tunnel, error)
```

`configJSON` выбирает провайдера полем `"provider"` (`max` | `wb`) и несёт
параметры туннеля. `StartTransport` минтит креды, поднимает пул DTLS-SRTP-стримов
и relay'ит UDP между локальным ртом и exit'ом.

- **`Protector`** — колбэк `protect(fd)`: Breach вешает его на свои TURN-сокеты,
  чтобы их трафик шёл **мимо** tun приложения. Без этого TURN-трафик зациклится
  в собственном туннеле и всё встанет. (В обход VpnService.)
- **`Logger`** — построчный лог в приложение.
- `LiveAllocations()` — сколько аллокаций сейчас живо; `CancelStarting()` —
  прервать длительный старт.

Kotlin (упрощённо):

```kotlin
val tunnel = Breachmobile.startTransport(configJson, protector, logger)
// ...
tunnel.stop()
```

## Конфиг

**MAX** — форма `maxproto.Config` (см. `config.example.json`): `token`,
`deviceId`, `userAgent{…}`, `mintMode` (`silent`/`call`), `server`, `wgListen`,
`streams`, `mints`, `dns`.

**WB** — `provider:"wb"` плюс:

```json
{
  "provider": "wb",
  "wbSession": "/data/.../wb.json",
  "wbChat": "chats/<id>",
  "server": "VPS_IP:48000",
  "wgListen": "127.0.0.1:51821",
  "streams": 4,
  "credCacheDir": "/data/.../creds"
}
```

## Логин

- **MAX по номеру:** `LoginByPhone(host, phone, identityJSON, deviceInfoJSON, asker)`
  — по SMS, возвращает токен + профиль; `BumpClientSession(configJSON)` крутит
  `clientSessionId` перед каждым стартом.
- **WB по WB ID:** `WBStartLogin(deviceID)` даёт ссылку и читает URL коллбэка,
  сохраняет сессию. Дальше: `WBListChats(session)` — список чатов на выбор,
  `WBResolvePeer(session, chat)` — проверить, что чат резолвится в одного пира
  (групповой не годится), `WBDeviceIDFromSession(session)` — id устройства сессии.

## Управление сервером из приложения

Деплой exit'а и управление без хранения SSH — отдельный документ:
[`server-provisioning.md`](server-provisioning.md) (`ProvisionServer`, `Server*`).
