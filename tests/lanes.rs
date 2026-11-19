//! Which relays a lane may name (its own process: `PUSHIR_RELAY` is
//! process-wide).

use pushir::Lane;

/// A lane names its relay by https, a host and nothing more: a peer's
/// lane never has a device dial a port of its own. Loopback only while
/// the device's own relay is, as a test's.
#[test]
fn a_lane_names_a_relay_by_https() {
    let id = "6e7a1cdd29b0b78fd13af4c5598feff4ef2a97166e3ca6f2e4fbfccd80505bf1";
    let lane = |r: &str| format!("pushir:{id}:{}@{r}", "03".repeat(32));
    let ok = |r: &str| lane(r).parse::<Lane>().is_ok();
    // SAFETY: the one test here, before any other thread reads it.
    unsafe { std::env::remove_var("PUSHIR_RELAY") };
    assert!(ok("https://irpush.cxn.center./"));
    assert!(ok("https://relay.example.org:8443/"));
    let l: Lane = lane("https://irpush.cxn.center./").parse().unwrap();
    assert_eq!(l.to_string(), lane("https://irpush.cxn.center./"));
    for r in [
        "http://relay.example.org/",
        "https://u:p@relay.example.org/",
        "https://relay.example.org/?x",
        "https://relay.example.org/#x",
        "https://localhost:631/",
        "http://127.0.0.1:631/",
        "https://0.0.0.0:631/",
        "https://[::ffff:127.0.0.1]:631/",
        "file:///etc/passwd",
    ] {
        assert!(!ok(r), "{r}");
    }
    // SAFETY: as above.
    unsafe { std::env::set_var("PUSHIR_RELAY", "http://127.0.0.1:3340/") };
    assert!(ok("http://127.0.0.1:3340/") && ok("http://[::1]:3341/"));
    assert!(!ok("http://relay.example.org/"));
}
