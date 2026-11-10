use anyhow::{Context, Result};
use data_encoding::HEXLOWER as HEX;
use iroh_base::SecretKey;
use std::io::{Read, Write};

fn key(f: &str) -> Result<SecretKey> {
    if !std::path::Path::new(f).exists() {
        std::fs::write(f, SecretKey::generate().to_bytes())?;
    }
    let b: [u8; 32] = std::fs::read(f)?.try_into().ok().context("bad key")?;
    Ok(SecretKey::from_bytes(&b))
}

fn slot(s: &str) -> Result<irpush::Slot> {
    HEX.decode(s.as_bytes())?.try_into().ok().context("a slot is 32 hex digits")
}

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let relay = irpush::relay();
    let sock = irpush::local::sock();
    match a[..] {
        ["daemon", k] => irpush::local::daemon(&sock, relay, key(k)?).await?,
        ["id", k] => println!("{}", key(k)?.public()),
        ["listen", s] => {
            let (id, mut rx) = irpush::local::attach(&sock, slot(s)?).await?;
            eprintln!("mailbox {id}");
            while let Some(m) = rx.recv().await {
                let mut o = std::io::stdout().lock();
                o.write_all(&(m.len() as u16).to_be_bytes())?;
                o.write_all(&m)?;
                o.flush()?;
            }
        }
        ["send", id, s] => {
            let mut b = vec![];
            std::io::stdin().read_to_end(&mut b)?;
            irpush::send(&relay, id.parse()?, slot(s)?, &b).await?
        }
        _ => eprintln!(
            "irpush daemon KEY | id KEY | listen SLOT | send ID SLOT < msg"
        ),
    }
    Ok(())
}
