# Building the Breach Android client (Kotlin)

How to embed the Breach tunnel in an Android app. The Go core ships as a
`gomobile` `.aar`; you drive it from Kotlin inside a `VpnService`.

> This document covers the **Breach transport** binding. The inner protocol
> (Hysteria2 / WireGuard), the tun device and routing are handled by
> **sing-box (libbox)** — a separate `.aar`. Breach only relays UDP over MAX
> TURN; sing-box dials Breach's local "mouth".

---

## 1. Architecture

```
┌─ Android VpnService (your app) ─────────────────────────────────────────┐
│                                                                          │
│   tun  ──►  sing-box / libbox            ──►  Breach transport (.aar)     │
│            (Hysteria2 client, tun,            (mouth 127.0.0.1:51821      │
│             routing, DNS)                       → MAX TURN → exit)        │
│                 │  Hy2 outbound server =            │                     │
│                 │  127.0.0.1:51821  ────────────────┘                     │
└──────────────────────────────────────────────────────────────────────────┘
                                     │
                        MAX TURN relay (155.212.x, TCP/UDP)
                                     │
                          Breach exit server (VPS :48000)
                                     │
                          Hysteria2 exit → internet
```

Two Go runtimes run in the app process: **libbox** (inner protocol + tun) and
**breach** (MAX-TURN transport). They talk over `127.0.0.1:51821` (the *mouth*).
Both must **protect every socket they open** from the VPN, or traffic loops back
into the tun and deadlocks (see §6).

---

## 2. Build the `breach.aar`

Prerequisites: Go 1.24+, Android SDK + NDK, `gomobile`.

```bash
go install golang.org/x/mobile/cmd/gomobile@latest
go install golang.org/x/mobile/cmd/gobind@latest
gomobile init

cd breach            # the Go module (module "breach")
gomobile bind \
  -target=android \
  -androidapi 21 \
  -javapkg ru.getbreach \
  -o breach.aar \
  ./mobile
```

- `-javapkg ru.getbreach` puts the generated classes under
  `ru.getbreach.breachmobile.*` (adjust to your app package).
- The `./mobile` package (`breachmobile`) uses cgo (pion DTLS/SRTP); the NDK
  toolchain is picked up by gomobile automatically.

Drop `breach.aar` into `app/libs/` and add to `build.gradle`:

```kotlin
dependencies {
    implementation(files("libs/breach.aar"))
    // your sing-box / libbox aar too
}
```

gomobile also emits a `breach-sources.jar` (Javadoc/param names) — keep it
alongside for IDE hints.

---

## 3. The API surface

From Go package `breachmobile` (generated class `Breachmobile`) — signatures as
seen from Kotlin:

```kotlin
// package ru.getbreach.breachmobile

object Breachmobile {
    // Start the transport. Blocks until the first allocation is up (~seconds),
    // or throws. Returns a Tunnel handle.
    fun startTransport(configJSON: String, p: Protector, l: Logger): Tunnel

    // Live allocation count — safe to poll any time, even during connect.
    fun liveAllocations(): Long

    // Abort an in-progress startTransport (user pressed Stop while "Connecting").
    fun cancelStarting()
}

interface Protector {           // you implement this
    fun protect(fd: Int): Boolean
}

interface Logger {              // you implement this (may be a no-op)
    fun log(line: String)
}

class Tunnel {
    fun stat(): String          // JSON snapshot for the UI
    fun diag(): String          // JSON per-stream diagnostics
    fun networkChanged()        // call on connectivity change
    fun stop()
}
```

`stat()` returns:
```json
{ "allocations": 16, "targetAllocations": 16, "clients": 1,
  "upPps": 40, "downPps": 38, "mbps": 24.3, "upBytes": …, "downBytes": …,
  "lastError": "" }
```

---

## 4. Config JSON

`startTransport` takes the same JSON schema as `breach/config.example.json`.
Minimum for a single account:

```json
{
  "host": "api2.oneme.ru",
  "port": 443,

  "token": "<MAX LOGIN token>",
  "deviceId": "<16-hex device id>",
  "instanceId": "<uuid>",
  "userAgent": {
    "deviceType": "ANDROID", "appVersion": "26.23.2", "osVersion": "Android 14",
    "timezone": "Europe/Moscow", "screen": "420dpi 420dpi 1080x2340",
    "pushDeviceType": "GCM", "arch": "arm64-v8a", "locale": "ru",
    "buildNumber": 6779, "deviceName": "Xiaomi 23127PN0CG", "deviceLocale": "ru"
  },

  "mintMode": "silent",
  "server": "<VPS ip>:48000",
  "wgListen": "127.0.0.1:51821",
  "streams": 4,
  "mints": 6,
  "turnTransport": "auto",
  "dns": "77.88.8.8:53"
}
```

Key fields:

| field | meaning |
|-------|---------|
| `token` + `deviceId` + `instanceId` | MAX identity. Get a token with `breach-client -login` (or the phone-auth flow); the token is bound to `deviceId`, so persist all three together. |
| `server` | the Breach exit `ip:port` (the VPS). **Required.** |
| `wgListen` | the local mouth sing-box dials. Default `127.0.0.1:51821`. |
| `streams` | allocations per credential (~4 saturates one credential ≈ 7 Mbit). |
| `mints` | credentials per account (throughput scales with mints up to ~4–6 ≈ 25–30 Mbit). |
| `turnTransport` | `auto` (default; UDP with a TCP fallback for UDP-blocked networks), `udp`, or `tcp`. |
| `dns` | resolver for the MAX API host (Android has no `/etc/resolv.conf`). |
| `accounts` | optional array — multiple MAX accounts, each `{token, deviceId, instanceId, userAgent}`; spreads the pool for more throughput. |

---

## 5. VpnService integration

```kotlin
import ru.getbreach.breachmobile.*

class BreachVpnService : VpnService() {

    private var tunnel: Tunnel? = null

    // Protect every fd Breach opens so its MAX-TURN / mint / DNS sockets go out
    // the real network, not the tun. This is the #1 correctness item.
    private val protector = object : Protector {
        override fun protect(fd: Int): Boolean = this@BreachVpnService.protect(fd)
    }

    private val logger = object : Logger {
        override fun log(line: String) { Log.i("breach", line) }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        // 1) establish the tun (this is sing-box's job in the full setup; shown
        //    minimally here). sing-box's PlatformInterface must ALSO protect().
        val tun = Builder()
            .setSession("Breach")
            .addAddress("10.9.0.2", 24)
            .addRoute("0.0.0.0", 0)
            .addDnsServer("1.1.1.1")
            .setMtu(1280)                 // headroom for ChannelData/relay
            .establish() ?: return START_NOT_STICKY

        // 2) start the Breach transport (mouth ← sing-box, mouth → MAX TURN)
        Thread {
            try {
                val cfg = loadConfigJson()          // your persisted config
                tunnel = Breachmobile.startTransport(cfg, protector, logger)
                // 3) start sing-box with Hy2 outbound → 127.0.0.1:51821, tun = `tun`
                startSingBox(tun)
            } catch (e: Exception) {
                Log.e("breach", "start failed", e)
                stopSelf()
            }
        }.start()

        return START_STICKY
    }

    override fun onDestroy() {
        tunnel?.stop()
        tunnel = null
        stopSingBox()
        super.onDestroy()
    }
}
```

### Connectivity changes

Register a `ConnectivityManager.NetworkCallback` and forward changes so Breach
re-probes UDP↔TCP and rebuilds its pool:

```kotlin
override fun onAvailable(network: Network) { tunnel?.networkChanged() }
override fun onLost(network: Network)     { tunnel?.networkChanged() }
```

### UI polling

```kotlin
// every ~1s on a background handler
val s = JSONObject(tunnel?.stat() ?: "{}")
val allocs = s.optInt("allocations")
val mbps   = s.optDouble("mbps")
val err    = s.optString("lastError")
// while still "Connecting", Breachmobile.liveAllocations() climbs before
// startTransport() returns.
```

### Stopping while connecting

If the user taps Stop before `startTransport` returns, call
`Breachmobile.cancelStarting()` — the pending start returns fast with an error
instead of blocking on the first allocation.

---

## 6. The sing-box (inner protocol) side

sing-box/libbox provides the tun, routing and the Hysteria2 client. Its outbound
points at the Breach mouth:

```jsonc
{
  "inbounds": [ { "type": "tun", "stack": "gvisor", ... } ],
  "outbounds": [ {
    "type": "hysteria2",
    "server": "127.0.0.1",
    "server_port": 51821,              // == wgListen mouth
    "password": "<hy2 password from provision-client>",
    "tls": { "enabled": true, "server_name": "www.bing.com",
             "insecure": true, "alpn": ["h3"] }
  } ]
}
```

**Both runtimes must protect their sockets.** libbox has its own hook
(`PlatformInterface` / `autoDetectInterfaceControl`) — wire it to
`VpnService.protect(fd)` exactly like Breach's `Protector`. If sing-box's Hy2
socket to `127.0.0.1:51821` weren't protected it would be fine (loopback), but
any non-loopback socket it opens must be protected.

> The mouth is plain loopback UDP, so sing-box → Breach needs no protection; only
> Breach's upstream sockets (MAX TURN, mint, DNS) and sing-box's own direct
> outbounds do.

---

## 7. In-app phone login (device spoofing)

The `breachmobile` package runs the full MAX phone-auth flow (sessionInit →
authRequest → SMS verify → optional 2FA → login) and lets the user pick which
device to impersonate.

You may spoof only the **cosmetic device fields** — `deviceName`, `osVersion`,
`screen`, `timezone`, `locale`, `deviceLocale`. The fingerprint-critical fields
(`appVersion`, `buildNumber`, `arch`, …) are locked to the build whose APK
digests the anti-spoof fingerprint uses, so no device info can ever make the
fingerprint contradict the announced version — which is why there are no presets
to keep in sync.

```kotlin
// optional: let the user set device info; empty fields keep the default
val deviceInfo = JSONObject().apply {
    put("deviceName", "samsung SM-S918B")
    put("osVersion", "Android 14")
    put("screen", "480dpi 480dpi 1440x3088")
    // timezone / locale / deviceLocale optional
}.toString()

// asker blocks until the UI supplies the code / 2FA password
val asker = object : LoginAsker {
    override fun askCode(): String = promptSmsCode()          // blocking
    override fun askPassword(hint: String): String = promptPassword(hint)
}
val res = Breachmobile.loginByPhone(
    /* host          */ "",                 // "" = api2.oneme.ru
    /* phone         */ "+7XXXXXXXXXX",
    /* identityJSON  */ savedIdentityJson,  // "" = fresh install; reuse on re-login
    /* deviceInfoJSON*/ deviceInfo,         // "" = default device
    asker,
)

// res.configJSON is the identity block (host/token/deviceId/instanceId/
// clientSessionId/userAgent/...). Merge your server + tunnel settings and PERSIST
// token + deviceId + instanceId together (losing deviceId = a new SMS).
```

On re-login pass the saved identity so the account keeps one device.

If you pass an empty `deviceInfoJSON` on a **fresh** login, a random device is
picked from an internal pool (so installs aren't all identical). On **re-login**
(a saved identity) an empty device keeps the stable default rather than
re-randomizing — pass the saved device to preserve the exact one.

### clientSessionId — increment every session

The real client's `clientSessionId` is a monotonic per-account counter that grows
by one on every use of the account. Before each `startTransport`, bump it and
persist:

```kotlin
val cfg = Breachmobile.bumpClientSession(savedConfigJson)  // clientSessionId += 1
saveConfig(cfg)
Breachmobile.startTransport(cfg, protector, logger)
```

Alternative to in-app login: `breach-client -login +7XXXXXXXXXX` on a desktop,
copy the printed block into the app config.

---

## 8. Checklist

- [ ] `breach.aar` built with `gomobile bind ./mobile`, dropped in `app/libs/`.
- [ ] `Protector.protect(fd)` → `VpnService.protect(fd)` for **Breach**.
- [ ] sing-box `PlatformInterface` protect wired the same way.
- [ ] tun MTU ≤ 1280.
- [ ] sing-box Hy2 outbound `server_port` == `wgListen` mouth.
- [ ] `networkChanged()` on connectivity callbacks.
- [ ] `cancelStarting()` on Stop-while-connecting; `stop()` on teardown.
- [ ] token + deviceId + instanceId persisted together.
- [ ] device spoofed via cosmetic fields only (deviceName/os/screen/locale).
- [ ] `bumpClientSession()` before each `startTransport`, result persisted.
