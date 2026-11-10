//! For android/pushir, in the app's own native library. The owner holds the
//! mailbox and hands each frame on unopened (`next`, told its lane by
//! `hears`); every app makes its own route key and opens its own frames.

#![allow(unsafe_code)]

use jni::errors::{Error, Result, ThrowRuntimeExAndDefault as Throw};
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jlong};
use jni::{Env, EnvUnowned};
use std::sync::{Mutex, OnceLock, mpsc};

static RX: OnceLock<Mutex<mpsc::Receiver<Vec<u8>>>> = OnceLock::new();
/// The mailbox's id, or why it did not start: started once only.
static ID: OnceLock<std::result::Result<String, String>> = OnceLock::new();

/// The mailbox, run on its own thread, with the key in `path`: its id.
fn start(path: &std::path::Path) -> anyhow::Result<String> {
    let sk = iroh_base::SecretKey::from_bytes(&crate::kept(path)?);
    let relay = crate::relay()?;
    // 64 frames wait for the owner's thread; more are a flood.
    let (tx, rx) = mpsc::sync_channel(64);
    let _ = RX.set(Mutex::new(rx));
    let id = sk.public().to_string();
    std::thread::spawn(move || {
        let rt =
            tokio::runtime::Builder::new_current_thread().enable_all().build();
        let on = |f: &[u8]| drop(tx.try_send(f.to_vec()));
        rt.expect("tokio").block_on(crate::listen(&relay, &sk, on))
    });
    Ok(id)
}

fn key(env: &Env, k: &JByteArray) -> Result<crate::Key> {
    let k = env.convert_byte_array(k)?.try_into();
    k.map_err(|_| Error::ParseFailed("a key is 32 bytes".into()))
}

/// Start the mailbox (once) with the key in `path`; its id.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_pushir_Native_start<'l>(
    mut env: EnvUnowned<'l>,
    _: JClass<'l>,
    path: JString<'l>,
) -> JString<'l> {
    env.with_env(|env: &mut Env<'l>| -> Result<_> {
        let path = path.to_string();
        let id = ID
            .get_or_init(|| start(path.as_ref()).map_err(|e| format!("{e:#}")));
        env.new_string(id.clone().map_err(Error::ParseFailed)?)
    })
    .resolve::<Throw>()
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
