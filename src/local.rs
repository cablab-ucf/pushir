//! One mailbox per desktop: `daemon` holds it, apps `attach` their lanes
//! over a Unix socket. The daemon knows a lane by its route key alone, so
//! it hands frames on unopened; 64 that no attached lane hears wait.

use crate::{FRAME, Key, hears, listen, open, route};
use anyhow::{Context, Result};
use iroh_base::{PublicKey, RelayUrl, SecretKey};
use std::collections::VecDeque;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{Receiver, Sender, channel, error::TrySendError};

/// Frames kept for lanes not attached, and for an app slow to read.
const HELD: usize = 64;

/// `$PUSHIR_SOCK`, or `$XDG_RUNTIME_DIR/pushir`, or `~/.pushir/sock`: in a
/// directory of the user's alone.
pub fn sock() -> PathBuf {
    let rt = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join("pushir"));
    let home = || std::env::home_dir().unwrap_or_default().join(".pushir/sock");
    std::env::var_os("PUSHIR_SOCK")
        .map(PathBuf::from)
        .or(rt)
        .unwrap_or_else(home)
}

#[derive(Default)]
struct Routes {
    on: Vec<(Key, Sender<Vec<u8>>)>,
    held: VecDeque<Vec<u8>>,
}

impl Routes {
    /// A frame goes to the attached lane that hears it; an app that reads
    /// too slowly loses it, one that left gives its place up. Any other
    /// frame waits, the oldest making way. Empty: a reconnection, for all.
    fn take(&mut self, f: &[u8]) {
        if f.is_empty() {
            return self.on.retain(|(_, t)| {
                !matches!(t.try_send(vec![]), Err(TrySendError::Closed(_)))
            });
        }
        if let Some(i) = self.on.iter().position(|(k, _)| hears(k, f)) {
            match self.on[i].1.try_send(f.to_vec()) {
                Err(TrySendError::Closed(_)) => drop(self.on.swap_remove(i)),
                _ => return,
            }
        }
        if self.held.len() == HELD {
            self.held.pop_front();
        }
        self.held.push_back(f.to_vec());
    }

    /// A lane attaches (its newest attachment has it): what waited for it.
    fn attach(&mut self, k: Key) -> Receiver<Vec<u8>> {
        let (tx, rx) = channel(HELD);
        self.on.retain(|(o, _)| *o != k);
        self.held.retain(|f| !hears(&k, f) || tx.try_send(f.clone()).is_err());
        self.on.push((k, tx));
        rx
    }
}

/// Hold mailbox `sk` on `relay` and serve apps on `sock`.
pub async fn daemon(sock: &Path, relay: RelayUrl, sk: SecretKey) -> Result<()> {
    if let Some(d) = sock.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(d)?;
    }
    let _ = std::fs::remove_file(sock);
    let l = UnixListener::bind(sock)?;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
    let r = Arc::new(Mutex::new(Routes::default()));
    let id = sk.public();
    let r2 = r.clone();
    tokio::spawn(async move {
        listen(&relay, &sk, |f| r2.lock().unwrap().take(f)).await
    });
    loop {
        let (mut c, _) = l.accept().await?;
        let r = r.clone();
        tokio::spawn(async move {
            let mut k = [0; 32];
            c.read_exact(&mut k).await?;
            c.write_all(id.as_bytes()).await?;
            let mut rx = r.lock().unwrap().attach(k);
            loop {
                tokio::select! {
                    m = rx.recv() => {
                        let Some(m) = m else { break };
                        c.write_all(&(m.len() as u16).to_be_bytes()).await?;
                        c.write_all(&m).await?;
                    }
                    // An app says nothing more: this is its leaving.
                    _ = c.read_u8() => break,
                }
            }
            anyhow::Ok(())
        });
    }
}

/// Attach lane `secret` to the daemon: the mailbox's id, and the lane's
/// messages, opened. An empty one says sync: a sender's bare wake, or the
/// mailbox back from a gap in which frames may have been missed.
pub async fn attach(
    sock: &Path,
    secret: &Key,
) -> Result<(PublicKey, Receiver<Vec<u8>>)> {
    let mut c = UnixStream::connect(sock).await.context("no pushir daemon")?;
    c.write_all(&route(secret)).await?;
    let mut id = [0; 32];
    c.read_exact(&mut id).await?;
    let (tx, rx) = channel(HELD);
    let secret = *secret;
    tokio::spawn(async move {
        let mut f = [0; FRAME];
        loop {
            // The app let go of its messages: tell the daemon by leaving.
            let n = tokio::select! {
                n = c.read_u16() => n? as usize,
                _ = tx.closed() => break,
            };
            c.read_exact(f.get_mut(..n).context("not a frame")?).await?;
            let m = if n == 0 { Some(vec![]) } else { open(&secret, &f[..n]) };
            if let Some(m) = m
                && tx.send(m).await.is_err()
            {
                break;
            }
        }
        anyhow::Ok(())
    });
    Ok((PublicKey::from_bytes(&id)?, rx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Lane, send};
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    /// A relay, a daemon on it, and a lane there by its secret's byte.
    async fn up(tag: &str) -> (Server, PathBuf, impl Fn(u8) -> Lane) {
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let s = Server::spawn(cfg).await.unwrap();
        let r: RelayUrl =
            format!("http://{}/", s.http_addr().unwrap()).parse().unwrap();
        let sk = SecretKey::generate();
        let id = sk.public();
        let sock = std::env::temp_dir()
            .join(format!("pushir-{tag}-{}/sock", std::process::id()));
        let (s2, r2) = (sock.clone(), r.clone());
        tokio::spawn(async move { daemon(&s2, r2, sk).await });
        sleep(Duration::from_millis(500)).await;
        (s, sock, move |k| Lane { relay: r.clone(), id, secret: [k; 32] })
    }

    /// What is heard within a second, gaps aside.
    async fn heard(rx: &mut Receiver<Vec<u8>>) -> Vec<Vec<u8>> {
        let mut v = vec![];
        while let Ok(Some(m)) = timeout(Duration::from_secs(1), rx.recv()).await
        {
            v.extend(Some(m).filter(|m| !m.is_empty()));
        }
        v
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn apps_share_one_mailbox_by_lane() {
        let (_s, sock, lane) = up("share").await;
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let (id, mut a) = attach(&sock, &[1; 32]).await.unwrap();
        let (_, mut b) = attach(&sock, &[2; 32]).await.unwrap();
        assert_eq!(id, lane(1).id);
        send(&lane(2), b"for b").await.unwrap();
        send(&lane(1), b"for a").await.unwrap();
        send(&lane(3), b"held").await.unwrap();
        assert_eq!(heard(&mut a).await, [b"for a"]);
        assert_eq!(heard(&mut b).await, [b"for b"]);
        let (_, mut c) = attach(&sock, &[3; 32]).await.unwrap();
        assert_eq!(heard(&mut c).await, [b"held"]);
        // An app that left loses nothing: its frames wait for its return.
        drop(a);
        for i in 0..3u8 {
            send(&lane(1), &[i]).await.unwrap();
            sleep(Duration::from_millis(200)).await;
        }
        let (_, mut a) = attach(&sock, &[1; 32]).await.unwrap();
        assert_eq!(heard(&mut a).await, [[0], [1], [2]]);
    }

    #[test]
    fn what_waits_is_bounded_and_the_newest() {
        // Frames for 100 lanes nobody attached, then 70 for one: 64 wait in
        // all, the newest.
        let mut r = Routes::default();
        for k in 100..200 {
            r.take(&crate::seal(&[k; 32], b"junk").unwrap());
        }
        for i in 0..70 {
            r.take(&crate::seal(&[9; 32], &[i]).unwrap());
        }
        assert_eq!(r.held.len(), HELD);
        let mut rx = r.attach(route(&[9; 32]));
        let got = std::iter::from_fn(|| rx.try_recv().ok());
        let got: Vec<u8> =
            got.map(|f| open(&[9; 32], &f).unwrap()[0]).collect();
        assert_eq!(got, (6..70).collect::<Vec<u8>>());
        assert!(r.held.is_empty() && r.on.len() == 1);
        // An app that does not read loses frames past 64; one that left, its place.
        for i in 0..70 {
            r.take(&crate::seal(&[9; 32], &[i]).unwrap());
        }
        assert!(r.held.is_empty());
        drop(rx);
        r.take(&crate::seal(&[9; 32], b"kept").unwrap());
        assert!(r.held.len() == 1 && r.on.is_empty());
    }
}
