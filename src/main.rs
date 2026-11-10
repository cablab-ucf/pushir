use anyhow::Result;
use iroh_base::SecretKey;
use pushir::{Lane, kept, local};
use std::io::{Read, Write};
use std::path::Path;

#[tokio::main]
async fn main() -> Result<()> {
    let a: Vec<String> = std::env::args().skip(1).collect();
    let a: Vec<&str> = a.iter().map(String::as_str).collect();
    let key = |f: &str| kept(Path::new(f)).map(|k| SecretKey::from_bytes(&k));
    let sock = local::sock();
    match a[..] {
        ["daemon", k] => {
            local::daemon(&sock, pushir::relay()?, key(k)?).await?
        }
        ["id", k] => println!("{}", key(k)?.public()),
        ["listen", f] => {
            let secret = kept(Path::new(f))?;
            let (id, mut rx) = local::attach(&sock, &secret).await?;
            eprintln!("{}", Lane { relay: pushir::relay()?, id, secret });
            while let Some(m) = rx.recv().await {
                let mut o = std::io::stdout().lock();
                o.write_all(&(m.len() as u16).to_be_bytes())?;
                o.write_all(&m)?;
                o.flush()?;
            }
        }
        ["send", lane] => {
            let mut b = vec![];
            std::io::stdin().read_to_end(&mut b)?;
            pushir::send(&lane.parse()?, &b).await?
        }
        _ => eprintln!(
            "pushir daemon KEY | id KEY | listen SECRET | send LANE < msg"
        ),
    }
    Ok(())
}
