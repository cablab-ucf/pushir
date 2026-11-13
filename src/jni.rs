//! For android/pushir, in the app's own native library. The owner holds the
//! mailbox and hands each frame on unopened (`next`, told its lane by
//! `hears`); every app makes its own route key and opens its own frames.

#![allow(unsafe_code)]

use jni::errors::{Error, Result, ThrowRuntimeExAndDefault as Throw};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jlong};
use jni::{Env, EnvUnowned};
use std::sync::{Mutex, OnceLock, mpsc};
use tokio::sync::watch;

static RX: OnceLock<Mutex<mpsc::Receiver<Vec<u8>>>> = OnceLock::new();
/// The mailbox's id, or why it did not start: started once only.
static ID: OnceLock<std::result::Result<String, String>> = OnceLock::new();
/// Whether the mailbox is held: while its broker runs. Let go, its
/// connection is closed, so the group's next owner holds it alone.
static HELD: OnceLock<watch::Sender<bool>> = OnceLock::new();

fn held() -> &'static watch::Sender<bool> {
    HELD.get_or_init(|| watch::channel(true).0)
}

/// The mailbox, run on its own thread, with the key in `path`: its id.
fn start(
    path: &std::path::Path,
    relay: iroh_base::RelayUrl,
) -> anyhow::Result<String> {
    let sk = iroh_base::SecretKey::from_bytes(&crate::kept(path)?);
    // 64 frames wait for the owner's thread; more are a flood.
    let (tx, rx) = mpsc::sync_channel(64);
    let _ = RX.set(Mutex::new(rx));
    let id = sk.public().to_string();
    let mut on = held().subscribe();
    std::thread::spawn(move || {
        let rt =
            tokio::runtime::Builder::new_current_thread().enable_all().build();
        let frame = |f: &[u8]| drop(tx.try_send(f.to_vec()));
        rt.expect("tokio").block_on(async {
            loop {
                let _ = on.wait_for(|h| *h).await;
                tokio::select! {
                    () = crate::listen(&relay, &sk, frame) => {}
                    _ = on.wait_for(|h| !*h) => {}
                }
            }
        })
    });
    Ok(id)
}

fn key(env: &Env, k: &JByteArray) -> Result<crate::Key> {
    let k = env.convert_byte_array(k)?.try_into();
    k.map_err(|_| Error::ParseFailed("a key is 32 bytes".into()))
}

/// Hold the mailbox (started once, with the key in `path`); its id.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_start<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    path: JString<'l>,
) -> JString<'l> {
    env.with_env(|env: &mut Env<'l>| -> Result<_> {
        let path = path.to_string();
        held().send_replace(true);
        let id = ID.get_or_init(|| {
            let id = crate::relay().and_then(|r| start(path.as_ref(), r));
            id.map_err(|e| format!("{e:#}"))
        });
        env.new_string(id.clone().map_err(Error::ParseFailed)?)
    })
    .resolve::<Throw>()
}

/// Let the mailbox go (its connection closed) until `start` again.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_stop<'l>(
    _: EnvUnowned<'l>,
    _: JClass<'l>,
) {
    held().send_replace(false);
}

/// The next frame, unopened; an empty one at each (re)connection. Blocks.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_next<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
) -> JByteArray<'l> {
    env.with_env(|env: &mut Env<'l>| -> Result<_> {
        let rx = RX.get().and_then(|rx| rx.lock().ok()?.recv().ok());
        env.byte_array_from_slice(
            &rx.ok_or(Error::ParseFailed("no mailbox".into()))?,
        )
    })
    .resolve::<Throw>()
}

/// A lane's route key, from its secret: what the owner knows the lane by.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_route<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    secret: JByteArray<'l>,
) -> JByteArray<'l> {
    env.with_env(|env: &mut Env<'l>| -> Result<_> {
        let route = crate::route(&key(env, &secret)?);
        env.byte_array_from_slice(&route)
    })
    .resolve::<Throw>()
}

/// Whether `frame` is for the lane of `route`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_hears<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    route: JByteArray<'l>,
    frame: JByteArray<'l>,
) -> jboolean {
    env.with_env(|env: &mut Env<'l>| -> Result<_> {
        Ok(crate::hears(&key(env, &route)?, &env.convert_byte_array(&frame)?))
    })
    .resolve::<Throw>()
}

/// The message `frame` carries for the lane of `secret`; null if not its own.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_open<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    secret: JByteArray<'l>,
    frame: JByteArray<'l>,
) -> JByteArray<'l> {
    env.with_env(|env: &mut Env<'l>| -> Result<_> {
        match crate::open(&key(env, &secret)?, &env.convert_byte_array(&frame)?)
        {
            Some(m) => env.byte_array_from_slice(&m),
            None => Ok(JByteArray::null()),
        }
    })
    .resolve::<Throw>()
}

/// Ping the relay now and wait for its answer: seconds until the next is due.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_kick<'l>(
    _: EnvUnowned<'l>,
    _: JClass<'l>,
) -> jlong {
    crate::kick() as jlong
}

#[cfg(test)]
mod tests {
    use super::*;
    use iroh_relay::server::{RelayConfig, Server, ServerConfig};
    use std::time::Duration;
    use tokio::time::timeout;

    /// The mailbox's next frame, empty at a (re)connection, within `s` s.
    fn next(s: u64) -> Option<Vec<u8>> {
        let rx = RX.get()?.lock().ok()?;
        rx.recv_timeout(Duration::from_secs(s)).ok()
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn a_mailbox_let_go_is_the_next_owners_alone_until_held_again() {
        let mut cfg = ServerConfig::default();
        cfg.relay = Some(RelayConfig::new(([127, 0, 0, 1], 0)));
        let s = Server::spawn(cfg).await.unwrap();
        let r = format!("http://{}/", s.http_addr().unwrap());
        let relay: iroh_base::RelayUrl = r.parse().unwrap();
        let dir = std::env::temp_dir();
        let path = dir.join(format!("pushir-{}.key", std::process::id()));
        start(&path, relay.clone()).unwrap();
        assert_eq!(next(10), Some(vec![]), "held");
        held().send_replace(false);
        // The next owner, with the same key, holds it: what is sent reaches
        // it, and the mailbox let go does not take it back.
        let sk = iroh_base::SecretKey::from_bytes(&crate::kept(&path).unwrap());
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let (r2, sk2) = (relay.clone(), sk.clone());
        let other = tokio::spawn(async move {
            crate::listen(&r2, &sk2, move |f| drop(tx.send(f.to_vec()))).await
        });
        let wait = Duration::from_secs(10);
        assert_eq!(timeout(wait, rx.recv()).await.unwrap(), Some(vec![]));
        let lane = crate::Lane { relay, id: sk.public(), secret: [1; 32] };
        crate::send(&lane, b"x").await.unwrap();
        let f = timeout(wait, rx.recv()).await.unwrap().unwrap();
        assert_eq!(crate::open(&lane.secret, &f).unwrap(), b"x");
        assert_eq!(next(3), None, "let go, yet back");
        other.abort();
        held().send_replace(true);
        assert_eq!(next(10), Some(vec![]), "held again");
        let _ = std::fs::remove_file(&path);
    }
}
