//! One mailbox per desktop: `daemon` holds it, apps `attach` by slot over
//! a Unix socket. Up to 64 frames wait for an app not attached.

use crate::{Slot, listen};
use anyhow::{Context, Result};
use iroh_base::{PublicKey, RelayUrl, SecretKey};
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc::{
    UnboundedReceiver, UnboundedSender, unbounded_channel,
};

/// `$IRPUSH_SOCK`, or `$XDG_RUNTIME_DIR/irpush`, or `~/.irpush.sock`.
pub fn sock() -> PathBuf {
    let rt = std::env::var_os("XDG_RUNTIME_DIR")
        .map(|d| PathBuf::from(d).join("irpush"));
    let home = || std::env::home_dir().unwrap_or_default().join(".irpush.sock");
    std::env::var_os("IRPUSH_SOCK")
        .map(PathBuf::from)
        .or(rt)
        .unwrap_or_else(home)
}

#[derive(Default)]
struct Routes {
    on: HashMap<Slot, UnboundedSender<Vec<u8>>>,
    held: HashMap<Slot, VecDeque<Vec<u8>>>,
}

/// Hold mailbox `sk` on `relay` and serve apps on `sock`.
pub async fn daemon(sock: &Path, relay: RelayUrl, sk: SecretKey) -> Result<()> {
    let _ = std::fs::remove_file(sock);
    let l = UnixListener::bind(sock)?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(sock, std::fs::Permissions::from_mode(0o600))?;
    let r = Arc::new(Mutex::new(Routes::default()));
    let id = sk.public();
    let r2 = r.clone();
    tokio::spawn(async move {
        let on = |slot: Slot, m: &[u8]| {
            let mut r = r2.lock().unwrap();
            if r.on.get(&slot).is_some_and(|t| t.send(m.to_vec()).is_ok()) {
                return;
            }
            let q = r.held.entry(slot).or_default();
            q.push_back(m.to_vec());
            q.truncate(64);
        };
        listen(&relay, &sk, Duration::from_secs(25 * 60), on).await
    });
    loop {
        let (mut c, _) = l.accept().await?;
        let r = r.clone();
        tokio::spawn(async move {
            let mut slot = [0; 16];
            c.read_exact(&mut slot).await?;
            c.write_all(id.as_bytes()).await?;
            let (tx, mut rx) = unbounded_channel();
            {
                let mut r = r.lock().unwrap();
                for m in r.held.remove(&slot).unwrap_or_default() {
                    let _ = tx.send(m);
                }
                r.on.insert(slot, tx);
            }
            while let Some(m) = rx.recv().await {
                c.write_all(&(m.len() as u16).to_be_bytes()).await?;
                c.write_all(&m).await?;
            }
            anyhow::Ok(())
        });
    }
}

/// Attach to the daemon as `slot`: the mailbox id, and its messages.
pub async fn attach(
    sock: &Path,
    slot: Slot,
) -> Result<(PublicKey, UnboundedReceiver<Vec<u8>>)> {
    let mut c = UnixStream::connect(sock).await.context("no irpush daemon")?;
    c.write_all(&slot).await?;
    let mut id = [0; 32];
    c.read_exact(&mut id).await?;
    let (tx, rx) = unbounded_channel();
    tokio::spawn(async move {
        loop {
            let n = c.read_u16().await? as usize;
            let mut m = vec![0; n];
            c.read_exact(&mut m).await?;
            if tx.send(m).is_err() {
                break anyhow::Ok(());
            }
        }
    });
    Ok((PublicKey::from_bytes(&id)?, rx))
}
