//! One relay connection per device, shared by its apps. A frame is an
//! app's slot and bytes the app sealed: irpush routes by slot and reads
//! nothing, for it holds no app key.

#![deny(unsafe_code)]

#[cfg(feature = "jni")]
mod jni;
#[cfg(unix)]
pub mod local;

use anyhow::{Context, Result, bail, ensure};
use futures_util::{SinkExt, StreamExt};
use iroh_base::{PublicKey, RelayUrl, SecretKey};
use iroh_relay::client::ClientBuilder;
use iroh_relay::protos::relay::{
    ClientToRelayMsg as Out, RelayToClientMsg as In,
};
use std::time::Duration;
use tokio::time::{Instant, sleep, sleep_until, timeout};

/// Every frame is this long, so the relay learns nothing from sizes.
pub const FRAME: usize = 1024;
pub const MAX: usize = FRAME - 18;
/// An app's address on a device: random, made by the app.
pub type Slot = [u8; 16];

/// The lab's irpush relay: pings a silent client after 130 min, not 16 s.
pub const RELAY: &str = "https://irpush.cxn.center./";

/// `$IRPUSH_RELAY`, or [`RELAY`].
pub fn relay() -> RelayUrl {
    let r = std::env::var("IRPUSH_RELAY").ok().and_then(|r| r.parse().ok());
    r.unwrap_or_else(|| RELAY.parse().expect("static relay url"))
}

fn roots() -> iroh_relay::tls::CaTlsConfig {
    #[cfg(not(target_os = "android"))]
    return iroh_relay::tls::CaTlsConfig::system();
    #[cfg(target_os = "android")]
    iroh_relay::tls::CaTlsConfig::embedded()
}

async fn connect(
    relay: &RelayUrl,
    sk: SecretKey,
) -> Result<iroh_relay::client::Client> {
    let tls = roots().client_config(irnet::tls())?;
    let b = ClientBuilder::new(
        relay.clone(),
        sk,
        iroh_dns::dns::DnsResolver::new(),
    );
    // As irnet's endpoint: through the network's proxy, if it has one.
    let proxy = ["HTTPS_PROXY", "https_proxy"]
        .iter()
        .find_map(|v| std::env::var(v).ok()?.parse().ok());
    let local = relay
        .host_str()
        .is_some_and(|h| h.starts_with("127.") || h == "localhost");
    let b = match proxy.filter(|_| !local) {
        Some(p) => b.proxy_url(p),
        None => b,
    };
    Ok(timeout(Duration::from_secs(10), b.tls_client_config(tls).connect())
        .await??)
}

/// Hand `msg` to `slot` at mailbox `to`, from a throwaway key.
pub async fn send(
    relay: &RelayUrl,
    to: PublicKey,
    slot: Slot,
    msg: &[u8],
) -> Result<()> {
    ensure!(msg.len() <= MAX, "over {MAX} bytes");
    let mut f = [&slot[..], &(msg.len() as u16).to_be_bytes()].concat();
    f.extend(msg);
    f.resize(FRAME, 0);
    let mut c = connect(relay, SecretKey::generate()).await?;
    c.send(Out::Datagrams { dst_endpoint_id: to, datagrams: f.into() }).await?;
    Ok(c.close().await?)
}

/// Hold mailbox `sk` on `relay`, pinging every `hb`, and hand each
/// (slot, message) to `on`. Reconnects forever.
pub async fn listen(
    relay: &RelayUrl,
    sk: &SecretKey,
    hb: Duration,
    on: impl Fn(Slot, &[u8]),
) {
    let mut wait = Duration::from_secs(1);
    loop {
        if session(relay, sk, hb, &on).await.is_ok() {
            wait = Duration::from_secs(1);
        }
        sleep(wait).await;
        wait = (wait * 2).min(Duration::from_secs(300));
    }
}

fn unframe(f: &[u8]) -> Option<(Slot, &[u8])> {
    let n = u16::from_be_bytes(f.get(16..18)?.try_into().ok()?) as usize;
    (f.len() == FRAME && n <= MAX)
        .then(|| (f[..16].try_into().unwrap(), &f[18..18 + n]))
}

async fn session(
    relay: &RelayUrl,
    sk: &SecretKey,
    hb: Duration,
    on: &impl Fn(Slot, &[u8]),
) -> Result<()> {
    let mut c = connect(relay, sk.clone()).await?;
    let (mut ping, mut due) = (None, Instant::now() + hb);
    loop {
        tokio::select! {
            m = c.next() => match m.context("closed")?? {
                In::Datagrams { datagrams, .. } => {
                    if let Some((slot, m)) = unframe(&datagrams.contents) {
                        on(slot, m);
                    }
                }
                In::Ping(d) => c.send(Out::Pong(d)).await?,
                In::Pong(d) if Some(d) == ping => (ping, due) = (None, Instant::now() + hb),
                _ => {}
            },
            _ = sleep_until(due) => {
                if ping.is_some() {
                    bail!("no pong");
                }
                let d = rand::random();
                c.send(Out::Ping(d)).await?;
                (ping, due) = (Some(d), Instant::now() + Duration::from_secs(15));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};

    #[tokio::test(flavor = "multi_thread")]
    async fn apps_share_one_mailbox_by_slot() {
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let s = Server::spawn(cfg).await.unwrap();
        let r: RelayUrl =
            format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
        let sk = SecretKey::generate();
        let id = sk.public();
        let sock =
            std::env::temp_dir().join(format!("irpush-{}", std::process::id()));
        let (s2, r2) = (sock.clone(), r.clone());
        tokio::spawn(async move { local::daemon(&s2, r2, sk).await });
        sleep(Duration::from_millis(300)).await;
        let (got, mut a) = local::attach(&sock, [1; 16]).await.unwrap();
        let (_, mut b) = local::attach(&sock, [2; 16]).await.unwrap();
        assert_eq!(got, id);
        sleep(Duration::from_millis(500)).await;
        send(&r, id, [2; 16], b"for b").await.unwrap();
        send(&r, id, [1; 16], b"for a").await.unwrap();
        send(&r, id, [3; 16], b"held").await.unwrap();
        assert_eq!(a.recv().await.unwrap(), b"for a");
        assert_eq!(b.recv().await.unwrap(), b"for b");
        sleep(Duration::from_millis(300)).await;
        let (_, mut c) = local::attach(&sock, [3; 16]).await.unwrap();
        assert_eq!(c.recv().await.unwrap(), b"held");
        assert!(send(&r, id, [1; 16], &[0; MAX + 1]).await.is_err());
    }
}
