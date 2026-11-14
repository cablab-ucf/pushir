//! A network move (its own process: the network is process-wide).

use iroh_base::{RelayUrl, SecretKey};
use iroh_relay::server::{RelayConfig, Server, ServerConfig};
use pushir::{Lane, listen, moved, open, send};
use std::time::{Duration, Instant};
use tokio::time::timeout;

const S10: Duration = Duration::from_secs(10);

/// Named first, nothing moves; moved, the connection is made anew at once
/// (no ping on the old first), and frames still come.
#[tokio::test(flavor = "multi_thread")]
async fn a_move_reconnects_at_once() {
    let mut cfg = ServerConfig::default();
    cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
    let s = Server::spawn(cfg).await.unwrap();
    let r: RelayUrl =
        format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
    let sk = SecretKey::generate();
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let (r2, k) = (r.clone(), sk.clone());
    tokio::spawn(async move {
        listen(&r2, &k, move |f| drop(tx.send(f.to_vec()))).await
    });
    moved("wifi");
    assert_eq!(
        timeout(S10, rx.recv()).await.unwrap(),
        Some(vec![]),
        "connected"
    );
    assert!(
        timeout(Duration::from_secs(2), rx.recv()).await.is_err(),
        "the first naming moves nothing"
    );
    let t = Instant::now();
    moved("cell");
    assert_eq!(
        timeout(S10, rx.recv()).await.unwrap(),
        Some(vec![]),
        "connected again"
    );
    assert!(t.elapsed() < Duration::from_secs(2), "at once: {:?}", t.elapsed());
    let lane = Lane { relay: r, id: sk.public(), secret: [4; 32] };
    send(&lane, b"after").await.unwrap();
    let f = timeout(S10, rx.recv()).await.unwrap().unwrap();
    assert_eq!(open(&lane.secret, &f).unwrap(), b"after");
}
