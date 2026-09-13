# Деплой и управление сервером из приложения

Поднять exit Breach на голом VPS **из приложения** (один заход по SSH), а дальше
управлять им **без хранения SSH-реквизитов** — через маленький admin-API на
exit'е с pinned-TLS. Модель Outline-менеджера: SSH один раз для установки, потом
навсегда — только ограниченный секрет.

```
┌ app ┐   SSH (однократно)   ┌ чистый VPS ┐
│      │ ───────────────────►│ install.sh │  Docker + breach-exit + breach-mgmt
│      │ ◄─── handle ─────────│            │  {url, secret, certSha256}
│      │   HTTPS (pinned) — add/list/remove/stats/routes, без SSH
│      │ ───────────────────► breach-mgmt (tcp/48000)
└──────┘
```

Из провижининга возвращаются два артефакта, хранятся раздельно:

| Артефакт | Что это | Кто выдаёт |
|---|---|---|
| **handle сервера** | `{url, host, port, secret, certSha256}` — управляет exit'ом | `breach-mgmt` (печатает при первом старте) |
| **provision-блок** | `{name, server, wireguard, hysteria2}` — конфиг одного клиента | `provision-client` |

Ни один сам по себе не является конфигом `StartTransport`. Конфиг туннеля —
слияние **идентичности мессенджера** (из логина) и **provision-блока** (с
сервера).

## 1. Установка в один тап: `ProvisionServer`

```go
func ProvisionServer(optionsJSON string, p Protector, progress ProvisionProgress) (*ProvisionResult, error)
```

`optionsJSON`:

```json
{
  "host": "1.2.3.4", "port": 22, "user": "root",
  "password": "…",              // ЛИБО "privateKey": "-----BEGIN …", "passphrase": "…"
  "proto": "hy2",               // hy2 (по умолч., без tun/caps) | both | wg | socks
  "relayPort": 48000,
  "clientName": "phoneA",
  "mgmtEnable": true,
  "hostKeyFingerprint": ""      // пусто = trust-on-first-use; задать = требовать совпадения
}
```

`ProvisionResult` (все строки, gomobile-safe):

- `ServerConfigJSON` — provision-блок.
- `HandleJSON` — **handle сервера**; сохрани его (Android Keystore) — по нему идут
  все дальнейшие вызовы управления. Пусто при `mgmtEnable=false`.
- `HostKeyFingerprint` — `SHA256:…` SSH-хост-ключа; сохрани и передавай обратно
  как `hostKeyFingerprint` при повторных SSH (пиннинг).

**После этого SSH-пароль/ключ можно выбросить** — больше не нужен.

## 2. Управление без SSH (handle-API)

Все берут handle JSON и опциональный `Protector` (передавай, только если tun
поднят — чтобы сокет шёл мимо него; иначе `null`). Fail-closed при несовпадении
TLS-пина, секрет в ошибках не светится.

```go
ServerCheck(handleJSON, p) (string, error)              // здоровье / валидация handle
ServerAddClient(handleJSON, name, p) (string, error)    // → новый provision-блок
ServerListClients(handleJSON, p) (string, error)        // [{name,address,wg,hy2}]
ServerRemoveClient(handleJSON, name, p) error
ServerStats(handleJSON, p) (string, error)              // {server:{…}, clients:[…]}
ServerSetRoutes(handleJSON, routeJSON, p) error         // "" сбрасывает политику
```

Имя клиента: `1–32` из `A–Z a–z 0–9 _ -` (проверяется и в приложении, и на сервере).

## 3. Сервер: `breach-mgmt`

HTTPS-сервис с фиксированным набором глаголов внутри exit-контейнера, обёртка над
теми же `provision-client`/`list-clients`/`remove-client`/`stats`/`set-routes`.
**Не** remote shell — утёкший секрет может только добавить/убрать VPN-юзера,
прочитать статистику или задать egress-политику, но не выполнить произвольную
команду и не получить root.

Глаголы: `GET /health`, `GET|POST /clients`, `DELETE /clients/<name>`,
`GET /stats`, `PUT /routes`.

- **Auth:** 32-байтный секрет в пути URL (сравнение constant-time) поверх
  **pinned self-signed** серта. CA нет — приложение пинит `certSha256`.
- **Состояние** (в томе `/etc/breach`, `0600`): `mgmt-secret`, `mgmt-cert.pem`,
  `mgmt-key.pem`, `mgmt.json` (полный handle для восстановления через
  `docker exec breach-exit cat /etc/breach/mgmt.json`).
- **Порт:** TCP, по умолчанию тот же номер, что и UDP-релей (`48000`). Открой этот
  **TCP**-порт и в файрволе, и в панели провайдера.
- Серт стабилен между рестартами; если не грузится — демон **не стартует**, а не
  молча ротирует пин.

### Выключить управление

| Переключатель | Где | Эффект |
|---|---|---|
| build-time `--build-arg MGMT=0` | `deploy/Dockerfile` | `breach-mgmt` вообще не компилируется и не попадает в образ |
| runtime `MGMT_ENABLE=0` | `.env` / compose | демон не запускается; exit только по SSH |

`breach-server` никогда не линкует `breach-mgmt` (отдельный бинарь за build-тегом
`mgmt`), так что data-path его не несёт.

## 4. Безопасность

- **Первый SSH — trust-on-first-use.** Без `hostKeyFingerprint` первое соединение
  принимает любой хост-ключ и возвращает его отпечаток для пиннинга. В недоверенной
  сети предпочитай ключ (подменённый хост не получит переиспользуемый секрет) или
  передавай отпечаток, показанный провайдером.
- **Handle несёт admin-секрет.** Храни в Android Keystore, не в открытых prefs.
- **Файрвол провайдера.** `install.sh` открывает порт в ufw/firewalld, но внешний
  облачный файрвол открывается вручную — иначе `ServerCheck` просто таймаутит.
