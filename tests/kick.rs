//! A kick, as Android's alarm makes it (its own process: kicks and their
//! answers are process-wide).

use iroh_base::{RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use pushir::{kick, listen};
use std::time::{Duration, Instant};
use tokio::time::timeout;

/// Online, a kick pings now and answers with the wait before the next
/// ping; offline, at once with the next try, a minute at least and
/// growing to five, so a phone with no network wakes ever less often.
#[tokio::test(flavor = "multi_thread")]
async fn a_kick_pings_now_and_offline_backs_off() {
    let mut cfg = ServerConfig::default();
    cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
    let s = Server::spawn(cfg).await.unwrap();
    let r: RelayUrl =
        format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
    // SAFETY: the one test here, before any other thread reads it.
    unsafe { std::env::set_var("PUSHIR_RELAY", r.as_str()) };
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        let on = move |f: &[u8]| _ = tx.send(f.len());
        listen(&r, &SecretKey::generate(), on).await
    });
    let s10 = Duration::from_secs(10);
    assert_eq!(timeout(s10, rx.recv()).await.unwrap(), Some(0), "connected");
    let kicked = || tokio::task::spawn_blocking(kick);
    // An early ping proves no longer wait: the first, 4 min.
    assert_eq!(kicked().await.unwrap(), 240, "answered");
    s.shutdown().await.unwrap();
    let mut got = vec![];
    while got.last() != Some(&300) {
        let t = Instant::now();
        got.push(kicked().await.unwrap());
        assert!(t.elapsed() < s10, "at once: {got:?}");
        assert!(got.len() < 15, "never five minutes: {got:?}");
    }
    assert!(got.iter().all(|&s| s >= 60), "{got:?}");
    assert!(got.is_sorted(), "{got:?}");
}
