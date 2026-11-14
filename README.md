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
  and grows by half with every answer, to 110 min (13 wakes a day, under
  the relay's own 130 min ping); a ping left unanswered means a NAT forgot
  the connection in that time, and the wait closes in on that limit from
  below. Any frame resets the silence. None can be skipped: a NAT forgets
  silently, and only the phone can find that out. Each kind of network
  keeps what it allows (`moved`), and a move to another network, or a new
  address, makes the connection anew at once, with no ping on the old.
- TLS 1.3 to the relay with X25519MLKEM768 and nothing else (irnet's
  `pq`, the one post-quantum setup these crates share; pushir takes that
  alone, not irnet's endpoint): a relay without it is refused. `http` only
  to this machine.
- pushir carries hints. What a hint announces is fetched over an irnet
  connection, proved by `irnet::psk` and as fast as QUIC goes.
- One connection carries a batch (`Sender`): a storage node ringing a
  hundred phones makes one handshake, not a hundred.

## Android

`android/pushir`: each app holds its own mailbox in its own foreground
service, so no app's pushes depend on another being installed, updated,
running or allowed to run. The app links this crate (feature `jni`) into
its native library.

```kotlin
// settings: include(":pushir"); project(":pushir").projectDir = file("pushir/android/pushir")
// app: implementation(project(":pushir"))
Pushir.start(this, "mylib", secret, onId = { mailbox -> }) { message -> }
Pushir.ask(activity)   // at setup, until false: the battery exemption, then notifications
Pushir.exempt(this)    // whether this app is exempt, for its settings to show
Pushir.stop(this)      // this app stops listening: its mailbox let go
```

Timers sleep with a phone, so an alarm (`setAndAllowWhileIdle`) makes each
ping, awake until it is answered or the connection is made anew; a network
coming up, or a connection lost, reconnects at once. Data wakes a phone for
a moment only: a frame the app opens keeps it awake 30 s, for the app to
show it and for the relay's ping that follows. `ask` matters: a vendor
kills the service of an app not exempt from battery optimisation, and only
an exempt app's alarm may restart it. The service runs with or without its
notification: shown (collapsed, under "Silent") only once the app may
notify. No iOS: it allows no such socket.

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

It is an iroh relay still, and the one with post-quantum TLS: irnet homes
every endpoint there first (then on iroh.cxn.center, then n0's).

`make relay-test` runs every test against that relay. It keeps its deployed
name, `irpush-relay` at `irpush.cxn.center`.

License: GPL-3.0-or-later.
