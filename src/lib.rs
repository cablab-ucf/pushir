//! One relay connection per device, shared by its apps. A frame is 1024
//! random-looking bytes sealed for an app's lane: the relay and whoever
//! holds the device's connection route it and read nothing.
//!
//! Frames are hints: one may be lost, repeated or late. An app syncs on
//! each, and on the empty message that follows every reconnect.

#![deny(unsafe_code)]

#[cfg(feature = "jni")]
mod jni;
#[cfg(unix)]
pub mod local;

use anyhow::{Context, Result, bail, ensure};
use aws_lc_rs::{aead, constant_time::verify_slices_are_equal, hmac, rand};
use data_encoding::HEXLOWER as HEX;
use futures_util::{SinkExt, StreamExt};
use iroh_base::{PublicKey, RelayUrl, SecretKey};
use iroh_dns::dns;
use iroh_relay::client::{Client, ClientBuilder};
use iroh_relay::protos::relay::{
    ClientToRelayMsg as Out, Datagrams, RelayToClientMsg as In,
};
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering::SeqCst};
use std::sync::{Condvar, LazyLock, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::Notify;
use tokio::time::{Instant, sleep, sleep_until, timeout};

/// Every frame is this long, so the relay learns nothing from sizes.
pub const FRAME: usize = 1024;
/// The longest message: a frame less its nonce, route tag, length and seal.
pub const MAX: usize = FRAME - 24 - 16 - 2 - 16;
pub type Key = [u8; 32];

/// The lab's relay for pushes: it pings a silent client after 130 min, not
/// 16 s, and keeps a frame until its mailbox has it.
pub const RELAY: &str = "https://irpush.cxn.center./";

/// `$PUSHIR_RELAY`, or [`RELAY`].
pub fn relay() -> Result<RelayUrl> {
    let r = std::env::var("PUSHIR_RELAY").unwrap_or_else(|_| RELAY.into());
    r.parse()
        .ok()
        .with_context(|| format!("PUSHIR_RELAY: {r} is no relay's url"))
}

/// Where an app hears: its device's mailbox on a relay, and the lane's
/// secret, under which its frames are sealed. For its senders alone:
/// `pushir:ID:SECRET@RELAY`.
#[derive(Clone, PartialEq, Eq)]
pub struct Lane {
    pub relay: RelayUrl,
    pub id: PublicKey,
    pub secret: Key,
}

impl std::fmt::Display for Lane {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "pushir:{}:{}@{}",
            self.id,
            HEX.encode(&self.secret),
            self.relay
        )
    }
}

impl std::str::FromStr for Lane {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        let lane = || {
            let (at, relay) = s.strip_prefix("pushir:")?.split_once('@')?;
            let (id, secret) = at.split_once(':')?;
            let secret = HEX.decode(secret.as_bytes()).ok()?.try_into().ok()?;
            let relay = relay.parse().ok().filter(dialable)?;
            Some(Lane { relay, id: id.parse().ok()?, secret })
        };
        lane().context("not a lane: pushir:ID:SECRET@RELAY, RELAY by https")
    }
}

/// 32 random bytes kept in `path` (mode 0600), made once: a mailbox's key
/// or a lane's secret.
pub fn kept(path: &Path) -> Result<Key> {
    if !path.exists() {
        let mut k = [0; 32];
        rand::fill(&mut k).ok().context("no randomness")?;
        let new = path.with_extension("new");
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut o, 0o600);
        std::io::Write::write_all(&mut o.open(&new)?, &k)?;
        // Whole or not at all, and never over a key made meanwhile. Android
        // lets an app make no hard link: there the file is moved into place.
        match std::fs::hard_link(&new, path) {
            Err(_) if !path.exists() => std::fs::rename(&new, path)?,
            _ => std::fs::remove_file(new)?,
        }
    }
    std::fs::read(path)?.try_into().ok().context("not a key: 32 bytes")
}

fn mac(key: &[u8], msg: &[u8]) -> Key {
    let key = hmac::Key::new(hmac::HMAC_SHA256, key);
    hmac::sign(&key, msg).as_ref().try_into().expect("32 bytes")
}

/// A lane's route key, for whoever holds the device's connection: it tells
/// which frames are the lane's and opens none.
pub fn route(secret: &Key) -> Key {
    mac(secret, b"pushir 1 route")
}

/// Whether `frame` is for the lane of `route`.
pub fn hears(route: &Key, frame: &[u8]) -> bool {
    frame.len() == FRAME
        && verify_slices_are_equal(
            &mac(route, &frame[..24])[..16],
            &frame[24..40],
        )
        .is_ok()
}

/// A frame's own key, from the lane's and the frame's 24 random bytes: no
/// two frames share one, so its nonce is constant.
fn cipher(secret: &Key, nonce: &[u8]) -> (aead::LessSafeKey, aead::Nonce) {
    let k = mac(&mac(secret, b"pushir 1 seal"), nonce);
    let k =
        aead::UnboundKey::new(&aead::CHACHA20_POLY1305, &k).expect("32 bytes");
    (aead::LessSafeKey::new(k), aead::Nonce::assume_unique_for_key([0; 12]))
}

/// nonce(24) ‖ route tag(16) ‖ sealed(length(2) ‖ message ‖ zeros) ‖ seal(16).
fn seal(secret: &Key, msg: &[u8]) -> Result<Vec<u8>> {
    ensure!(msg.len() <= MAX, "over {MAX} bytes");
    let mut f = vec![0; FRAME - 16];
    rand::fill(&mut f[..24]).ok().context("no randomness")?;
    let (head, body) = f.split_at_mut(40);
    let tag = mac(&route(secret), &head[..24]);
    head[24..].copy_from_slice(&tag[..16]);
    body[..2].copy_from_slice(&(msg.len() as u16).to_be_bytes());
    body[2..2 + msg.len()].copy_from_slice(msg);
    let (key, nonce) = cipher(secret, &head[..24]);
    let tag = key.seal_in_place_separate_tag(
        nonce,
        aead::Aad::from(&head[24..]),
        body,
    );
    f.extend_from_slice(tag.ok().context("seal")?.as_ref());
    Ok(f)
}

/// The message `frame` carries, if it is sealed for this lane.
pub fn open(secret: &Key, frame: &[u8]) -> Option<Vec<u8>> {
    hears(&route(secret), frame).then_some(())?;
    let (key, nonce) = cipher(secret, &frame[..24]);
    let mut body = frame[40..].to_vec();
    let m = key
        .open_in_place(nonce, aead::Aad::from(&frame[24..40]), &mut body)
        .ok()?;
    let n = u16::from_be_bytes([m[0], m[1]]) as usize;
    m.get(2..2 + n).map(<[u8]>::to_vec)
}

fn roots() -> iroh_relay::tls::CaTlsConfig {
    #[cfg(not(target_os = "android"))]
    return iroh_relay::tls::CaTlsConfig::system();
    #[cfg(target_os = "android")]
    iroh_relay::tls::CaTlsConfig::embedded()
}

/// Whether `relay` is this device itself (0.0.0.0 and ::ffff:127.0.0.1
/// reach it too).
fn loopback(relay: &RelayUrl) -> bool {
    let me = |ip: IpAddr| ip.is_loopback() || ip.is_unspecified();
    match relay.host() {
        Some(url::Host::Ipv4(ip)) => me(ip.into()),
        Some(url::Host::Ipv6(ip)) => me(ip.to_canonical()),
        Some(url::Host::Domain(name)) => {
            matches!(name, "localhost" | "localhost.")
        }
        None => false,
    }
}

/// Whether `relay` may be dialled: by https, with nothing but a host, port
/// and path. Loopback (by http too) only while this device's own relay
/// ([`relay`]) is loopback, a test's: a peer's lane reaches no local port.
fn dialable(relay: &RelayUrl) -> bool {
    let bare = relay.username().is_empty()
        && relay.password().is_none()
        && relay.query().is_none()
        && relay.fragment().is_none();
    let local = || cfg!(test) || crate::relay().is_ok_and(|r| loopback(&r));
    bare && match loopback(relay) {
        false => relay.scheme() == "https",
        true => matches!(relay.scheme(), "http" | "https") && local(),
    }
}

/// Names as the system resolves them (getaddrinfo), which honours each
/// network's DNS and Android's Private DNS. iroh's own resolver reads
/// Android's DNS servers through JNI and panics with no activity (a boot,
/// an update): with `panic = "abort"` the process dies, pushes and all.
#[derive(Debug)]
struct System;

type Found<T> = std::pin::Pin<
    Box<
        dyn Future<Output = Result<dns::BoxIter<T>, dns::DnsError>>
            + Send
            + 'static,
    >,
>;

impl System {
    fn find<T: Send + 'static>(
        host: String,
        of: fn(IpAddr) -> Option<T>,
    ) -> Found<T> {
        Box::pin(async move {
            let found = tokio::net::lookup_host((host, 0)).await;
            let found = found.map_err(n0_error::AnyError::from)?;
            let ips: Vec<T> = found.filter_map(|a| of(a.ip())).collect();
            Ok(Box::new(ips.into_iter()) as dns::BoxIter<T>)
        })
    }
}

impl dns::Resolver for System {
    fn lookup_ipv4(&self, host: String) -> Found<Ipv4Addr> {
        Self::find(host, |ip| match ip {
            IpAddr::V4(ip) => Some(ip),
            _ => None,
        })
    }

    fn lookup_ipv6(&self, host: String) -> Found<Ipv6Addr> {
        Self::find(host, |ip| match ip {
            IpAddr::V6(ip) => Some(ip),
            _ => None,
        })
    }

    fn lookup_txt(&self, _: String) -> Found<dns::TxtRecordData> {
        Box::pin(async { Err(n0_error::AnyError::from("no TXT lookups"))? })
    }

    fn clear_cache(&self) {}

    fn reset(&self) -> Box<dyn dns::Resolver> {
        Box::new(System)
    }
}

/// One for the process: it holds nothing but the system's.
static DNS: LazyLock<dns::DnsResolver> =
    LazyLock::new(|| dns::DnsResolver::custom(System));

async fn connect(relay: &RelayUrl, sk: SecretKey) -> Result<Client> {
    ensure!(dialable(relay), "{relay}: a relay is reached by https");
    let local = loopback(relay);
    // irnet's hybrid alone: a relay without it is refused, not met
    // classically, for this hop hides who is sent to from a recording.
    let tls = roots().client_config(irnet::pq())?;
    let b = ClientBuilder::new(relay.clone(), sk, DNS.clone());
    // Through the network's proxy, if it has one.
    let proxy = ["HTTPS_PROXY", "https_proxy"]
        .iter()
        .find_map(|v| std::env::var(v).ok()?.parse().ok());
    let b = match proxy.filter(|_| !local) {
        Some(p) => b.proxy_url(p),
        None => b,
    };
    Ok(timeout(Duration::from_secs(10), b.tls_client_config(tls).connect())
        .await??)
}

/// A nameless connection to a relay (a throwaway key) for any number of
/// frames to mailboxes there: one handshake for a batch, not one each.
pub struct Sender(RelayUrl, Client);

impl Sender {
    pub async fn connect(relay: &RelayUrl) -> Result<Self> {
        Ok(Self(relay.clone(), connect(relay, SecretKey::generate()).await?))
    }

    /// Hand `msg`, sealed, to lane `to`. `Ok` is not delivery: only a reply
    /// is.
    pub async fn send(&mut self, to: &Lane, msg: &[u8]) -> Result<()> {
        ensure!(to.relay == self.0, "lane on another relay: {}", to.relay);
        let mut d = Datagrams::from(seal(&to.secret, msg)?);
        // Congestion-experienced, which no QUIC sender sets: by it the
        // relay tells a pushir frame from iroh's traffic.
        d.ecn = Some(noq_proto::EcnCodepoint::Ce);
        Ok(self
            .1
            .send(Out::Datagrams { dst_endpoint_id: to.id, datagrams: d })
            .await?)
    }

    pub async fn close(mut self) -> Result<()> {
        Ok(self.1.close().await?)
    }
}

/// Hand `msg`, sealed, to lane `to`: a [`Sender`] for this one frame.
pub async fn send(to: &Lane, msg: &[u8]) -> Result<()> {
    let mut s = Sender::connect(&to.relay).await?;
    s.send(to, msg).await?;
    s.close().await
}

/// The shortest and the longest silence before a ping, and how long its
/// pong may take.
const LO: Duration = Duration::from_secs(4 * 60);
/// Half an hour: a silent NAT drop costs at most this long before a ping
/// finds it, and many NATs forget an idle connection not much later.
const HI: Duration = Duration::from_secs(30 * 60);
const PONG: Duration = Duration::from_secs(15);
/// How long a kick waits: past a pong's deadline and a reconnection, so a
/// dead connection is found and replaced in the one wake.
const KICKED: Duration = Duration::from_secs(30);

/// How long the connection may stay silent before it is pinged. A ping
/// wakes a phone's radio for some ten seconds, so the wait grows by half
/// after every answered ping, to 30 min (48 a day). A ping left
/// unanswered means a NAT forgot the connection within that silence: the
/// wait returns to the last one answered and closes in on the limit from
/// below, by halves. Each network keeps what it was found to allow
/// ([`moved`]), so a phone that comes back to one learns it once.
struct Beat {
    wait: Duration,
    /// The longest silence a ping was answered after, if `wait` rests on one.
    good: Duration,
    /// The shortest silence known to lose the connection.
    bad: Duration,
}

impl Beat {
    const fn new() -> Self {
        Self { wait: LO, good: Duration::ZERO, bad: Duration::MAX }
    }

    /// A ping after `quiet` was answered (one sent early proves nothing).
    fn answered(&mut self, quiet: Duration) {
        if quiet + PONG < self.wait {
            return;
        }
        self.good = quiet;
        let half = quiet.saturating_add(self.bad.saturating_sub(quiet) / 2);
        let next = (quiet * 3 / 2).min(HI).min(half);
        // Within a sixteenth of the limit is near enough.
        if next > self.wait + self.wait / 16 {
            self.wait = next;
        }
    }

    /// A ping after `quiet` went unanswered, or the connection broke on it.
    fn unanswered(&mut self, quiet: Duration) {
        self.bad = quiet;
        if self.good.is_zero() || self.good >= quiet {
            self.good = Duration::ZERO;
            self.wait = (quiet * 2 / 3).max(LO / 4);
        } else {
            self.wait = self.good;
        }
    }
}

/// Wakes the session to ping now, and tells [`kick`] of each answer: its
/// count, and the wait before the next ping (or, offline, the next try).
static KICK: Notify = Notify::const_new();
static PULSE: (Mutex<(u64, Duration)>, Condvar) =
    (Mutex::new((0, LO)), Condvar::new());

fn pulse(wait: Duration) {
    let mut p = PULSE.0.lock().unwrap_or_else(|e| e.into_inner());
    *p = (p.0 + 1, wait);
    PULSE.1.notify_all();
}

/// Ping the relay now, reconnecting if it does not answer, and wait up to
/// 30 s for the answer (or the reconnection, or its failure): the seconds
/// until this is next due. For a platform whose timers sleep with it (Android's alarm
/// calls this, awake as long) and for a network that just came back.
/// Blocks: not for an async task.
pub fn kick() -> u64 {
    let p = PULSE.0.lock().unwrap_or_else(|e| e.into_inner());
    let n = p.0;
    // Whoever waits now, and the next to wait if none does.
    KICK.notify_waiters();
    KICK.notify_one();
    let wait = PULSE.1.wait_timeout_while(p, KICKED, |p| p.0 == n);
    let (p, late) = wait.unwrap_or_else(|e| e.into_inner());
    if late.timed_out() { 60 } else { p.1.as_secs() }
}

/// The network the device is on, as its platform names it ("wifi",
/// "cell"), and how often it moved: each move ends the connection.
static NET: Mutex<String> = Mutex::new(String::new());
static MOVES: AtomicU64 = AtomicU64::new(0);
static MOVED: Notify = Notify::const_new();

/// The device is on network `net` now, or its address changed there: the
/// connection on the old one is dropped (no ping first) and one made on
/// this at once. The first naming moves nothing.
pub fn moved(net: &str) {
    let mut n = NET.lock().unwrap_or_else(|e| e.into_inner());
    let first = n.is_empty();
    *n = net.into();
    if !first {
        MOVES.fetch_add(1, SeqCst);
        MOVED.notify_waiters();
    }
}

/// The mailboxes this process holds, by id: how many [`listen`]s hold
/// each, and how many of those are on its relay now.
static HELD: Mutex<BTreeMap<[u8; 32], (u32, u32)>> =
    Mutex::new(BTreeMap::new());

/// One [`listen`]'s part in [`HELD`], given back as it ends or is dropped.
struct Held([u8; 32], bool);

impl Held {
    fn tally(&self, held: i32, up: i32) {
        let mut m = HELD.lock().unwrap_or_else(|e| e.into_inner());
        let e = m.entry(self.0).or_default();
        e.0 = e.0.saturating_add_signed(held);
        e.1 = e.1.saturating_add_signed(up);
        if e.0 == 0 {
            m.remove(&self.0);
        }
    }

    fn up(&mut self, up: bool) {
        if self.1 != up {
            self.tally(0, if up { 1 } else { -1 });
            self.1 = up;
        }
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.up(false);
        self.tally(-1, 0);
    }
}

/// Whether mailbox `id`, held by this process, is on its relay now (its
/// last ping answered, or none yet due): what proves its lane between
/// frames, at no cost. `None`: not held here (another process's, such as
/// the daemon's).
pub fn up(id: &PublicKey) -> Option<bool> {
    let m = HELD.lock().unwrap_or_else(|e| e.into_inner());
    m.get(id.as_bytes()).map(|e| e.1 > 0)
}

/// Hold mailbox `sk` on `relay` and hand each frame to `on`, unopened; an
/// empty one tells of a (re)connection, before which frames may have been
/// missed. Reconnects forever.
pub async fn listen(relay: &RelayUrl, sk: &SecretKey, on: impl Fn(&[u8])) {
    let mut beats: HashMap<String, Beat> = HashMap::new();
    let mut wait = Duration::from_secs(1);
    let mut held = Held(*sk.public().as_bytes(), false);
    held.tally(1, 0);
    loop {
        let (at, moves) = (Instant::now(), MOVES.load(SeqCst));
        if let Ok(c) = connect(relay, sk.clone()).await {
            let net = NET.lock().unwrap_or_else(|e| e.into_inner()).clone();
            let beat = beats.entry(net).or_insert_with(Beat::new);
            held.up(true);
            let _ = session(c, &on, beat, moves).await;
            held.up(false);
            // Moved, or connected a while then lost: again at once. A
            // timer sleeps with a phone, so waiting would hold what the
            // relay keeps for us until something else wakes it.
            if MOVES.load(SeqCst) != moves || at.elapsed() >= wait {
                wait = Duration::from_secs(1);
                continue;
            }
        }
        wait = (wait * 2).min(Duration::from_secs(300));
        // Offline: a kick has its answer now, the next try (a minute at
        // least, for a phone's alarm), not a wake each minute held 30 s.
        pulse(wait.max(LO / 4));
        tokio::select! {
            _ = sleep(wait) => {}
            _ = KICK.notified() => {}
        }
    }
}

async fn session(
    mut c: Client,
    on: &impl Fn(&[u8]),
    beat: &mut Beat,
    moves: u64,
) -> Result<()> {
    on(&[]);
    pulse(beat.wait);
    // When the relay was last heard, by the clock that runs while the
    // device sleeps; the ping awaited, the silence it broke, its deadline.
    let mut heard = SystemTime::now();
    let mut ping: Option<([u8; 8], Duration, Instant)> = None;
    let run = async {
        loop {
            ensure!(MOVES.load(SeqCst) == moves, "moved");
            // A clock set back: due now (its pong sets `heard` anew).
            let quiet = heard.elapsed().unwrap_or(beat.wait);
            // Timers stop while the device sleeps: look at the clock again
            // within a minute of waking.
            let nap =
                beat.wait.saturating_sub(quiet).min(Duration::from_secs(60));
            let until = ping.map_or(Instant::now() + nap, |p| p.2);
            let mut kicked = false;
            tokio::select! {
                m = c.next() => match m.context("closed")?? {
                    In::Datagrams { datagrams, .. } => {
                        heard = SystemTime::now();
                        if datagrams.contents.len() == FRAME {
                            on(&datagrams.contents);
                        }
                    }
                    In::Ping(d) => {
                        c.send(Out::Pong(d)).await?;
                        heard = SystemTime::now();
                    }
                    In::Pong(d) if ping.is_some_and(|p| p.0 == d) => {
                        beat.answered(ping.take().expect("some").1);
                        heard = SystemTime::now();
                        pulse(beat.wait);
                    }
                    _ => {}
                },
                _ = sleep_until(until) => {}
                _ = KICK.notified() => kicked = true,
                _ = MOVED.notified() => continue,
            }
            let quiet = heard.elapsed().unwrap_or(beat.wait);
            match ping {
                Some((_, _, dead)) if Instant::now() >= dead => {
                    bail!("no pong")
                }
                None if kicked || quiet >= beat.wait => {
                    let mut d = [0; 8];
                    rand::fill(&mut d).ok().context("no randomness")?;
                    c.send(Out::Ping(d)).await?;
                    ping = Some((d, quiet, Instant::now() + PONG));
                }
                _ => {}
            }
        }
    };
    let end: Result<()> = run.await;
    // Lost while a ping was out, not moved: the silence before it was too
    // long. Lost otherwise (moved, the relay restarted): nothing learnt.
    if let Some((_, quiet, _)) = ping.filter(|_| MOVES.load(SeqCst) == moves) {
        beat.unanswered(quiet);
    }
    end
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};

    async fn relay() -> (Server, RelayUrl) {
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let s = Server::spawn(cfg).await.unwrap();
        let r = format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
        (s, r)
    }

    fn lane(relay: &RelayUrl, id: PublicKey, k: u8) -> Lane {
        Lane { relay: relay.clone(), id, secret: [k; 32] }
    }

    /// What `listen` hands on next that is not a (re)connection.
    async fn frame(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        loop {
            let f =
                timeout(Duration::from_secs(10), rx.recv()).await.ok()??;
            if !f.is_empty() {
                return Some(f);
            }
        }
    }

    fn mailbox(
        r: &RelayUrl,
        sk: &SecretKey,
    ) -> tokio::sync::mpsc::UnboundedReceiver<Vec<u8>> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let (r, sk) = (r.clone(), sk.clone());
        tokio::spawn(async move {
            listen(&r, &sk, move |f| drop(tx.send(f.to_vec()))).await
        });
        rx
    }

    /// A relay's name is resolved by the system, no JNI asked (none can be
    /// had on Android without an activity), and connected to.
    #[tokio::test(flavor = "multi_thread")]
    async fn names_resolve_as_the_system_does() {
        let url = "http://localhost/".parse().unwrap();
        let ips: Vec<_> =
            DNS.resolve_host_all(&url, PONG).collect::<Vec<_>>().await;
        assert!(ips.iter().flatten().any(IpAddr::is_loopback), "{ips:?}");
        let (s, _) = relay().await;
        let port = s.http_addr().unwrap().port();
        let r = format!("http://localhost:{port}/").parse().unwrap();
        connect(&r, SecretKey::generate()).await.unwrap();
    }

    #[test]
    fn only_loopback_gets_the_local_relay_policy() {
        for (host, local) in [
            ("127.0.0.2", true),
            ("[::1]", true),
            ("localhost.", true),
            ("0.0.0.0", true),
            ("[::ffff:127.0.0.1]", true),
            ("127.office.example", false),
            ("[::2]", false),
            ("[::ffff:10.0.0.1]", false),
        ] {
            assert_eq!(
                loopback(&format!("http://{host}/").parse().unwrap()),
                local
            );
        }
    }

    /// The wire as chatir v0.4.5 and later peers speak it (CLAUDE.md): a
    /// frame sealed then opens and routes as it did, and a lane reads the
    /// same. A change here strands every phone running an older one.
    #[test]
    fn the_wire_is_as_chatir_v0_4_5() {
        let f = include_bytes!("../tests/v0.4.frame");
        assert_eq!((FRAME, MAX), (1024, 966));
        assert_eq!(open(&[3; 32], f).as_deref(), Some(&b"v0.4.5"[..]));
        let r = route(&[3; 32]);
        assert!(hears(&r, f));
        let hex = data_encoding::HEXLOWER.encode(&r);
        assert_eq!(
            hex,
            "0c2b23177a6648f4f239b3d6f608a78bdc5c5ead1ae2a673beb67104b1fa8c2f"
        );
        let id = SecretKey::from_bytes(&[5; 32]).public();
        let l = Lane { relay: RELAY.parse().unwrap(), id, secret: [3; 32] };
        let s = "pushir:6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1:\
                 0303030303030303030303030303030303030303030303030303030303030303\
                 @https://irpush.cxn.center./";
        assert_eq!(l.to_string(), s);
        assert!(s.parse::<Lane>().unwrap() == l);
        assert_eq!(RELAY, "https://irpush.cxn.center./");
    }

    #[test]
    fn a_frame_opens_for_its_lane_alone_and_tells_nothing() {
        let (a, b) = ([1; 32], [2; 32]);
        for m in [&b""[..], b"hello", &[7; MAX]] {
            let f = seal(&a, m).unwrap();
            assert_eq!(f.len(), FRAME);
            assert_eq!(open(&a, &f).as_deref(), Some(m));
            assert!(hears(&route(&a), &f) && !hears(&route(&b), &f));
            assert!(open(&b, &f).is_none());
            // No frame repeats a byte run of another: slot, length and
            // padding are all under the seal.
            let g = seal(&a, m).unwrap();
            assert!(f[..40] != g[..40] && f[40..] != g[40..]);
        }
        assert!(seal(&a, &[0; MAX + 1]).is_err());
        // The route key routes; it opens nothing and forges nothing.
        let mut f = seal(&a, b"x").unwrap();
        assert!(open(&route(&a), &f).is_none());
        f[100] ^= 1;
        assert!(hears(&route(&a), &f) && open(&a, &f).is_none());
        let l = Lane {
            relay: RELAY.parse().unwrap(),
            id: SecretKey::generate().public(),
            secret: a,
        };
        assert!(l.to_string().parse::<Lane>().unwrap() == l);
        assert!("pushir:x@y".parse::<Lane>().is_err());
    }

    #[test]
    fn the_beat_grows_and_settles_under_a_wait_that_failed() {
        let min = |m: u64| Duration::from_secs(m * 60);
        let mut b = Beat::new();
        for _ in 0..12 {
            b.answered(b.wait);
        }
        assert_eq!(b.wait, HI);
        // A kick's early ping proves no wait.
        b.wait = min(6);
        b.answered(min(1));
        assert_eq!(b.wait, min(6));
        // A NAT that forgets after 15 min: three probes past it fail (20,
        // 17, 15.2), then the wait rests at 13.5 and none is lost.
        let mut b = Beat::new();
        let mut lost = vec![];
        for i in 0..40 {
            match b.wait < min(15) {
                true => b.answered(b.wait),
                false => {
                    lost.push(i);
                    b.unanswered(b.wait)
                }
            }
        }
        assert_eq!(b.wait, Duration::from_secs(810));
        assert_eq!(lost, [4, 6, 8]);
        // One that forgets sooner than the first wait: found from above.
        let mut b = Beat::new();
        for _ in 0..40 {
            match b.wait < min(3) {
                true => b.answered(b.wait),
                false => b.unanswered(b.wait),
            }
        }
        assert!(b.wait < min(3) && b.wait >= min(2), "{:?}", b.wait);
    }

    #[test]
    fn a_key_is_kept_private_and_whole() {
        let p = std::env::temp_dir()
            .join(format!("pushir-key-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let k = kept(&p).unwrap();
        assert_eq!(kept(&p).unwrap(), k);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        std::fs::write(&p, [0; 31]).unwrap();
        assert!(kept(&p).is_err());
        std::fs::remove_file(&p).unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_batch_reaches_its_lanes_and_a_reconnection_is_told() {
        let (s, r) = relay().await;
        let sk = SecretKey::generate();
        let mut rx = mailbox(&r, &sk);
        assert_eq!(rx.recv().await.unwrap(), b"", "connected");
        let (a, b) = (lane(&r, sk.public(), 1), lane(&r, sk.public(), 2));
        let mut tx = Sender::connect(&r).await.unwrap();
        tx.send(&a, b"for a").await.unwrap();
        tx.send(&b, b"for b").await.unwrap();
        assert!(
            tx.send(&lane(&RELAY.parse().unwrap(), sk.public(), 1), b"")
                .await
                .is_err()
        );
        tx.close().await.unwrap();
        let (f, g) =
            (frame(&mut rx).await.unwrap(), frame(&mut rx).await.unwrap());
        assert_eq!(open(&a.secret, &f).unwrap(), b"for a");
        assert_eq!(open(&b.secret, &g).unwrap(), b"for b");
        assert!(open(&a.secret, &g).is_none());
        // The relay restarts: the mailbox comes back by itself and says so.
        let at = s.http_addr().unwrap();
        s.shutdown().await.unwrap();
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(at));
        let _s = Server::spawn(cfg).await.unwrap();
        let again = timeout(Duration::from_secs(20), rx.recv()).await;
        assert_eq!(again.unwrap().unwrap(), b"", "reconnected");
        send(&a, b"after").await.unwrap();
        assert_eq!(
            open(&a.secret, &frame(&mut rx).await.unwrap()).unwrap(),
            b"after"
        );
        assert!(
            connect(&"http://example.org/".parse().unwrap(), sk).await.is_err()
        );
    }

    /// `up` says what this process holds: on its relay, off it, or gone.
    #[tokio::test(flavor = "multi_thread")]
    async fn up_says_whether_the_mailbox_is_on_its_relay() {
        let (s, r) = relay().await;
        let sk = SecretKey::generate();
        assert_eq!(up(&sk.public()), None, "not held here");
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (r2, sk2) = (r.clone(), sk.clone());
        let l = tokio::spawn(async move {
            listen(&r2, &sk2, move |f| drop(tx.send(f.to_vec()))).await
        });
        assert_eq!(rx.recv().await.unwrap(), b"", "connected");
        assert_eq!(up(&sk.public()), Some(true));
        // A frame through it: the relay has the connection, so its
        // shutdown closes it (one not yet registered would outlive it).
        send(&lane(&r, sk.public(), 1), b"").await.unwrap();
        assert!(frame(&mut rx).await.is_some());
        s.shutdown().await.unwrap();
        timeout(Duration::from_secs(10), async {
            while up(&sk.public()) != Some(false) {
                sleep(Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("off its relay once that is gone");
        l.abort();
        let _ = l.await;
        assert_eq!(up(&sk.public()), None, "let go");
    }

    /// With the lab's relay (`make relay-test`: deploy/relay-hold.patch): a
    /// frame for a mailbox that is away waits for it, and one handed to a
    /// connection that dies before answering is handed over again.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn the_relay_keeps_a_frame_until_its_mailbox_has_it() {
        let (_s, r) = relay().await;
        let sk = SecretKey::generate();
        let a = lane(&r, sk.public(), 1);
        send(&a, b"while away").await.unwrap();
        // A connection that takes the frame and dies without a pong.
        let mut c = connect(&r, sk.clone()).await.unwrap();
        let got = loop {
            if let In::Datagrams { datagrams, .. } =
                c.next().await.unwrap().unwrap()
            {
                break datagrams.contents;
            }
        };
        assert_eq!(open(&a.secret, &got).unwrap(), b"while away");
        drop(c);
        let mut rx = mailbox(&r, &sk);
        assert_eq!(
            open(&a.secret, &frame(&mut rx).await.unwrap()).unwrap(),
            b"while away"
        );
        // Answered now: a third connection is handed nothing.
        sleep(Duration::from_millis(500)).await;
        let mut c = connect(&r, sk.clone()).await.unwrap();
        let more = timeout(Duration::from_secs(2), async {
            loop {
                if let In::Datagrams { .. } = c.next().await.unwrap().unwrap() {
                    break;
                }
            }
        });
        assert!(more.await.is_err(), "handed over twice after its pong");
    }

    /// With the lab's relay: a flood to one mailbox is cut to a burst of 64
    /// and one a second after, and of what waits for a mailbox that is away
    /// the newest 64 are kept.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore]
    async fn the_relay_bounds_a_flood() {
        let (_s, r) = relay().await;
        let sk = SecretKey::generate();
        let a = lane(&r, sk.public(), 1);
        let mut tx = Sender::connect(&r).await.unwrap();
        for i in 0..100u8 {
            tx.send(&a, &[i]).await.unwrap();
        }
        tx.close().await.unwrap();
        sleep(Duration::from_millis(500)).await;
        let mut rx = mailbox(&r, &sk);
        let mut got = vec![];
        while let Ok(Some(f)) = timeout(Duration::from_secs(2), rx.recv()).await
        {
            got.extend(
                open(&a.secret, &f).filter(|m| !m.is_empty()).map(|m| m[0]),
            );
        }
        assert_eq!(
            got,
            (36..100).collect::<Vec<u8>>(),
            "the newest 64, in order"
        );
        // Connected: 64 at once, then about one a second.
        let mut tx = Sender::connect(&r).await.unwrap();
        for i in 0..200u8 {
            tx.send(&a, &[i]).await.unwrap();
        }
        tx.close().await.unwrap();
        let mut n = 0;
        while let Ok(Some(f)) = timeout(Duration::from_secs(2), rx.recv()).await
        {
            n += open(&a.secret, &f).is_some() as usize;
        }
        assert!((64..=70).contains(&n), "{n} of 200 passed");
    }
}
