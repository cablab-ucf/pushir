//! For android/irpush, in the app's own native library: the owner runs
//! the mailbox; `next` hands it each frame as slot ‖ message.

#![allow(unsafe_code)]

use jni::JNIEnv;
use jni::objects::{JClass, JString};
use jni::sys::{jbyteArray, jstring};
use std::sync::{Mutex, OnceLock, mpsc};

static RX: OnceLock<Mutex<mpsc::Receiver<Vec<u8>>>> = OnceLock::new();
static ID: OnceLock<String> = OnceLock::new();

/// Start the mailbox (once) with the key in `path`; its id.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_start(
    mut env: JNIEnv,
    _: JClass,
    path: JString,
) -> jstring {
    let path: String =
        env.get_string(&path).map(Into::into).unwrap_or_default();
    let id = ID.get_or_init(|| {
        let p = std::path::Path::new(&path);
        if !p.exists() {
            let _ =
                std::fs::write(p, iroh_base::SecretKey::generate().to_bytes());
        }
        let Some(b) =
            std::fs::read(p).ok().and_then(|b| <[u8; 32]>::try_from(b).ok())
        else {
            return String::new();
        };
        let sk = iroh_base::SecretKey::from_bytes(&b);
        let (tx, rx) = mpsc::channel();
        let _ = RX.set(Mutex::new(rx));
        let id = sk.public().to_string();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Runtime::new().expect("tokio");
            let on =
                |s: crate::Slot, m: &[u8]| drop(tx.send([&s[..], m].concat()));
            rt.block_on(crate::listen(
                &crate::relay(),
                &sk,
                std::time::Duration::from_secs(600),
                on,
            ))
        });
        id
    });
    env.new_string(id).map(|s| s.into_raw()).unwrap_or(std::ptr::null_mut())
}

/// The next frame: blocks.
#[unsafe(no_mangle)]
pub extern "system" fn Java_org_irpush_Native_next(
    env: JNIEnv,
    _: JClass,
) -> jbyteArray {
    let m = RX
        .get()
        .and_then(|r| r.lock().unwrap().recv().ok())
        .unwrap_or_default();
    env.byte_array_from_slice(&m)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}
