# In-app server provisioning & management

Deploy a Breach exit onto a bare VPS **from the app** (one SSH pass), then manage
it **without keeping SSH credentials** — through a small pinned-TLS admin API on
the exit. This is the Outline-manager model: SSH once to install, a scoped secret
forever after.

```
┌ app ┐   SSH (once)         ┌ fresh VPS ┐
│      │ ───────────────────►│ install.sh│  Docker + breach-exit + breach-mgmt
│      │ ◄─── handle ────────│           │  {url, secret, certSha256}
│      │                     └───────────┘
│      │   HTTPS (pinned) — add/list/remove/stats/routes, no SSH
│      │ ───────────────────► breach-mgmt (tcp/48000)
└──────┘
```

Two artifacts come back from provisioning and are stored separately:

| Artifact | What it is | Produced by |
|---|---|---|
| **server handle** | `{url, host, port, secret, certSha256}` — manages the exit | `breach-mgmt` (printed at first boot) |
| **provision block** | `{name, server, wireguard, hysteria2}` — one client's exit config | `provision-client` |

Neither is a `StartTransport` config on its own. The tunnel config is the app’s
merge of a **MAX identity** (from `LoginByPhone`) + a **provision block** (from a
server) — the same `ConfigImport.fromProvisionBlock` + `CoreConfigBuilder` path
you already use for a manually-imported block.

---

## 1. One-tap install: `ProvisionServer`

```go
func ProvisionServer(optionsJSON string, p Protector, progress ProvisionProgress) (*ProvisionResult, error)
```

`optionsJSON`:

```json
{
  "host": "1.2.3.4",
  "port": 22,
  "user": "root",
  "password": "…",           // OR "privateKey": "-----BEGIN …", "passphrase": "…"
  "proto": "hy2",            // hy2 (default, no tun/caps needed) | both | wg
  "relayPort": 48000,
  "clientName": "phoneA",
  "mgmtEnable": true,        // default true
  "hostKeyFingerprint": ""   // empty = trust-on-first-use; set to require a match
}
```

`ProvisionResult` (all strings, gomobile-safe):

- `ServerConfigJSON` — the provision block → feed to `ConfigImport.fromProvisionBlock`.
- `HandleJSON` — the **server handle** → persist it (Android Keystore); this is
  what all later management calls take. Empty if `mgmtEnable=false`.
- `HostKeyFingerprint` — `SHA256:…` of the box’s SSH host key. Store it and pass
  it back as `hostKeyFingerprint` on any later SSH to that box (pin-on-repeat).

Kotlin:

```kotlin
val opts = JSONObject()
  .put("host", host).put("password", pass)
  .put("proto", "hy2").put("clientName", "phoneA")
  .toString()

val res = Breachmobile.provisionServer(opts, /* Protector or */ null,
  object : ProvisionProgress { override fun line(s: String) = appendLog(s) })

saveServerHandle(res.handleJSON)                 // manage without SSH from now on
val server = ConfigImport.fromProvisionBlock(res.serverConfigJSON)
// then: CoreConfigBuilder.build(server, maxAccount, …) → BumpClientSession → startTransport
```

**After this, discard the SSH password/key** — it is never needed again.

---

## 2. Manage without SSH (the handle API)

All take the handle JSON and an optional `Protector` (pass one only if a tun is
up so the socket bypasses it; else `null`). They fail closed on a TLS-pin
mismatch and never surface the secret in an error.

```go
ServerCheck(handleJSON string, p Protector) (string, error)               // health / validate handle
ServerAddClient(handleJSON, name string, p Protector) (string, error)     // → a new provision block
ServerListClients(handleJSON string, p Protector) (string, error)         // [{name,address,wg,hy2}]
ServerRemoveClient(handleJSON, name string, p Protector) error
ServerStats(handleJSON string, p Protector) (string, error)               // {server:{…}, clients:[…]}
ServerSetRoutes(handleJSON, routeJSON string, p Protector) error          // "" clears the policy
```

```kotlin
val block = Breachmobile.serverAddClient(handleJSON, "tablet", null)  // add a device
val server = ConfigImport.fromProvisionBlock(block)                   // → a profile
Breachmobile.serverRemoveClient(handleJSON, "tablet", null)           // revoke
```

Client `name`: `1–32` of `A–Z a–z 0–9 _ -` (enforced app- and server-side).

> **The old JSch `SshAdmin` is gone.** The Android client deleted it (and the JSch
> dependency) in favour of `ProvisionServer` for setup plus the handle API for
> everything after; see `android/app/src/main/java/pw/komet/breach/data/ServerAdmin.kt`.
> Servers added before the handle existed have none, and are shown as
> "management unavailable — deploy again" rather than silently failing.

---

## 3. The server side: `breach-mgmt`

A fixed-verb HTTPS service inside the exit container that wraps the same
`provision-client`/`list-clients`/`remove-client`/`stats`/`set-routes` tools.
**Not** a remote shell — a leaked secret can only add/remove a VPN user, read
stats or set the egress policy, never run an arbitrary command or gain root.

Verbs: `GET /health`, `GET|POST /clients`, `DELETE /clients/<name>`,
`GET /stats`, `PUT /routes`.

`PUT /routes` takes `{"route": <sing-box "route" object>}` or `{"clear": true}`
and hands the object to `set-routes` base64-encoded, so nothing in it reaches a
shell. It is NEWER than the other verbs: an exit installed from an image built
before it answers `404 no such endpoint`, which the app reports as "redeploy to
enable this" rather than pretending the policy was applied. Note that a
block-everything policy can cut the exit off from the internet, and undoing that
needs SSH.

- **Auth**: a 32-byte secret in the URL path (constant-time compared) over a
  **pinned self-signed TLS cert**. No CA. The app pins `certSha256`.
- **State** (in the `/etc/breach` volume, `0600`): `mgmt-secret`, `mgmt-cert.pem`,
  `mgmt-key.pem`, and `mgmt.json` (the full handle, for recovery via
  `docker exec breach-exit cat /etc/breach/mgmt.json`).
- **Port**: TCP, same number as the UDP relay by default (`48000`). Open that TCP
  port in the firewall **and the VPS provider’s panel**.
- The cert is stable across restarts; if it ever fails to load, the daemon
  **refuses to start** rather than silently rotating the pin.

### Turning management off

Two independent switches:

| Switch | Where | Effect |
|---|---|---|
| **Build-time** `--build-arg MGMT=0` | `deploy/Dockerfile` | `breach-mgmt` is **never compiled or shipped** — the code isn’t in the image at all. (Published image builds with `MGMT=1`.) |
| **Runtime** `MGMT_ENABLE=0` | `.env` / compose | The daemon isn’t started; the exit is SSH-only. The published image honors this without a rebuild. |

`breach-server` never links `breach-mgmt` (separate binary behind the `mgmt`
build tag), so the exit’s data path carries none of it regardless.

---

## 4. Security notes

- **First SSH is trust-on-first-use.** With no `hostKeyFingerprint`, the first
  connection accepts whatever host key is presented and reports its fingerprint
  to pin next time. On an untrusted network prefer **key auth** (a spoofed host
  never gets a reusable secret) or pass the provider-shown host key as
  `hostKeyFingerprint`. The provisioner warns when you use a password with no
  pinned fingerprint.
- **The handle carries the admin secret.** Store it in the Android Keystore, not
  plaintext prefs; it grants add/remove-client + stats over the exit.
- **Provider firewall.** `install.sh` opens the port in ufw/firewalld, but an
  external cloud firewall must be opened by hand — otherwise `ServerCheck` just
  times out.
