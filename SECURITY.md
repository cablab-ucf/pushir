# Security

pushir wakes a sleeping device: senders push sealed 1 KiB frames to the
device's mailbox on an iroh relay; the device's app opens them. Report a
vulnerability privately (GitHub security advisory on this repository).

## Who is trusted with what

| Party | Can | Cannot |
|---|---|---|
| Relay operator | see which mailbox gets frames, when, from which connection; drop, delay or replay frames | read or forge a frame; hold a mailbox without its secret key |
| Anyone who knows a mailbox id | send junk frames (rate-limited: 64, then 1/s, past that batched each 60 s) | have them opened, or delivered as an app's |
| Holder of a lane (`pushir:ID:SECRET@RELAY`) | push frames that open; point its own lane at any public https relay | make a sender dial plain http, userinfo, a loopback port, or any address in the sender's own network (by name or number) |

## Cryptography

- A frame's key is HMAC(HMAC(secret, "pushir 1 seal"), 192-bit random
  nonce); the AEAD's zero nonce is therefore unique per key. Length and
  padding are under the seal; frames are always 1024 bytes.
- Routing: HMAC(route key, nonce) truncated to 128 bits, compared in constant
  time and in the AEAD's associated data. The route key routes only.
- The relay hop: TLS 1.3 with X25519MLKEM768 only; holding a mailbox needs
  a signature by its key (iroh-relay's handshake).
- The receiver drops a frame whose nonce it saw among the last 256.

## Delivery

The relay (deploy/relay-hold.patch) holds frames for a mailbox that is away,
evicting the oldest held anywhere when full, and hands them on as it comes
back. On the device, a full queue never drops silently: an empty frame (the
wire's "catch up") follows once there is room. Pings keep the longest
silence at 30 minutes; offline, retries back off to 5 minutes.

## Known limits (accepted, with reason)

- A sender's batch of frames goes over one connection: the relay sees that
  those mailboxes were pushed by one sender at once.
- A flood of junk to a mailbox at or below 1 frame/s still wakes its device
  each time (the relay cannot tell junk from frames).
- A fast flood (about 65,000 frames) can push others' held frames out, the
  oldest first.
- Android holds a 30 s wakelock per opened frame: apps (chatir, pasa) do
  their work on a thread of their own and rely on it. Shortening it needs
  each app to hold its own, checked on a phone asleep: planned after v0.5.0.
- A lane may point at another's mailbox id: frames to it do not open there
  (the secret differs), but they wake it, within the relay's rate limits.
- Replay detection is per mailbox, the last 256 frames, this process.

## Wire compatibility

Frames, lanes and the relay protocol stay as chatir v0.4.5 peers speak them;
`the_wire_is_as_chatir_v0_4_5` pins it.
