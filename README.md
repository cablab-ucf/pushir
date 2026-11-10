# pushir

One relay connection per device, shared by all its apps: a phone holds one
quiet socket instead of one per app. A frame is 1024 random-looking bytes
sealed for an app's lane: the relay, and whoever holds the device's
connection, route it and read nothing.

```rust
let lane: Lane = "pushir:ID:SECRET@RELAY".parse()?;           // from the app that hears there
pushir::send(&lane, b"up to 966 bytes").await?;               // any sender; a Sender for a batch
let (mailbox, mut rx) = pushir::local::attach(&sock, &secret).await?; // desktop app
```

```sh
pushir daemon KEY        # desktop: hold the mailbox (one per device)
pushir listen SECRET     # attach the lane whose secret is kept in SECRET: its address, then
                         # u16 length + message per push on stdout
pushir send LANE < m     # PUSHIR_RELAY (default irpush.cxn.center), PUSHIR_SOCK
```

- A lane is a mailbox and a 32-byte secret, made by the app and given to
  its senders alone. From the secret come a seal key and a route key; a
  frame is `nonce(24) ‖ HMAC(route key, nonce)[..16] ‖ sealed message`
  (ChaCha20-Poly1305 under a key of its own, padded to 1024 bytes). Whoever
  holds the device's connection (the daemon, another app on a phone) is
  given route keys only: it tells a lane's frames and can neither open nor
  forge one. The relay sees mailbox ids, IPs and timing: not which app, not
  a length. Senders use throwaway keys.
- Frames are hints: one may be lost, repeated or late. An app syncs on
  each, and on the empty message it gets after every reconnection (frames
  may have been missed). The lab's relay keeps a frame until its mailbox
  answers a ping sent after it (64 per mailbox, the newest; a day), in
  memory, so a restart loses them; elsewhere sends are best effort. What
  must not be lost belongs on a device of yours that stays up.
- One lane's senders share its secret: a frame says "from one of them", so
  an app that must know which sends that inside. A mailbox id is the same
  for every app of the device: peers of two apps can tell they meet one
  device.
- Battery: the connection is pinged after a silence that starts at 4 min
  and grows by half with every answer, to 28 min (51 wakes a day: by
  estimate, not yet measured, under 1 % of a phone's battery on mobile
  data and far less on Wi-Fi); a ping left
  unanswered means a NAT forgot the connection in that time, and the wait
  closes in on that limit from below. Any frame resets the silence.
- TLS 1.3 to the relay with X25519MLKEM768 and nothing else: a relay
  without it is refused. `http` only to this machine.
- One connection carries a batch (`Sender`): a storage node ringing a
  hundred phones makes one handshake, not a hundred.

## Android

`android/pushir`: apps of one group (same signing key) share one
connection; the one installed first owns it and runs a foreground service.
The app links this crate (feature `jni`) into its native library.

```kotlin
// settings: include(":pushir"); project(":pushir").projectDir = file("pushir/android/pushir")
// app: implementation(project(":pushir")); manifestPlaceholders["pushirGroup"] = "com.example"
Pushir.start(this, "mylib", secret, onId = { mailbox -> }) { message -> }
```

The owner knows each app's lane by its route key, wakes an app that is not
running, and keeps 64 frames for those. Timers sleep with a phone, so an
alarm (`setAndAllowWhileIdle`) makes each ping, and a network coming up
reconnects at once. Ask the user to exempt the owner from battery
optimisation where a vendor kills foreground services. No iOS: it allows
no such socket.

## Relay

`deploy/`: iroh's relay with four patches, on NixOS (`make deploy HOST=ip`,
then `make update`) or Debian (`deploy/debian.sh`). Set `deploy/config.nix`.

- `relay-ping`: pings a silent client after 130 min (stock relays ping
  every 16-20 s, which drains a phone).
- `relay-pq`: X25519MLKEM768 first.
- `relay-unlimited`: a key lifts the rate limit, for big transfers that
  cannot go direct.
- `relay-hold`: keeps a pushir frame (marked ECN-CE, which no QUIC sender
  sets, so iroh's traffic is never touched) until its mailbox pongs it;
  hands a connected mailbox 64 at once, then one a second; 65,536 in all.

`make relay-test` runs every test against that relay. It keeps its deployed
name, `irpush-relay` at `irpush.cxn.center`.

License: GPL-3.0-or-later.
