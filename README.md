# irpush

One relay connection per device, shared by all its apps: a phone holds one
quiet socket instead of one per app. A frame is an app's 16-byte slot and
bytes the app sealed; irpush routes by slot and holds no app key, so it
reads nothing.

```rust
irpush::send(&relay, mailbox, slot, &sealed).await?;          // any sender
let (mailbox, mut rx) = irpush::local::attach(&sock, slot).await?; // desktop app
```

```sh
irpush daemon KEY        # desktop: hold the mailbox (one per device)
irpush listen SLOT       # attach: u16 length + message per push on stdout
irpush send ID SLOT < m  # IRPUSH_RELAY (default irpush.cxn.center), IRPUSH_SOCK
```

- Every frame is 1024 bytes. The relay sees ids, IPs and timing only;
  senders use throwaway keys. Frames for an app not attached wait (64).
- Apps authenticate and open their own frames (pasa: the time, sealed under
  the pairing key). A slot reveals nothing but "the same app as before".
- TLS 1.3 to the relay, X25519MLKEM768 first. Pings every 10 min (phones)
  or 25 min (desktops).

## Android

`android/irpush`: apps of one group (same signing key) share one
connection; the one installed first owns it and runs a foreground service.
The app links this crate (feature `jni`) into its native library.

```kotlin
// settings: include(":irpush"); project(":irpush").projectDir = file("irpush/android/irpush")
// app: implementation(project(":irpush")); manifestPlaceholders["irpushGroup"] = "com.example"
Irpush.start(this, "mylib", slot, onId = { mailbox -> }) { sealed -> }
```

## Relay

`deploy/`: iroh's relay with a 130 min ping (stock relays ping every
16-20 s, which drains a phone), on NixOS (`make deploy HOST=ip`, then
`make update`) or Debian (`deploy/debian.sh`). Set `deploy/config.nix`.

License: GPL-3.0-or-later.
