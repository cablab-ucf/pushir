#!/bin/sh
# pushir's relay on Debian/Ubuntu, without Nix: no token, pings after 130 min,
# post-quantum TLS, keys lift the rate limit, frames kept until their mailbox
# has them, address discovery on UDP 7842.
# As root, from a checkout of this repository at a commit you trust:
#   sh deploy/debian.sh irpush.example.org admin@example.org
set -eu
dom=${1:?usage: debian.sh DOMAIN EMAIL}
mail=${2:?usage: debian.sh DOMAIN EMAIL}
v=1.4.1
sum=7e5589e7c1475700686603a970275687f760df853bc6525c7eb1347aa31d7230 # crates.io's checksum of iroh-relay $v
here=$(cd "$(dirname "$0")" && pwd)
src=/var/cache/irpush-relay

apt-get update -q
apt-get install -yq curl build-essential pkg-config cmake patch

# Built by a user of its own, not root: cargo runs every crate's build script.
id irpush-build >/dev/null 2>&1 || useradd --system --home-dir "$src" --shell /usr/sbin/nologin irpush-build
rm -rf "$src" && install -d -o irpush-build "$src"
install -m644 "$here"/relay-*.patch "$here/iroh-relay.Cargo.lock" "$src"
runuser -u irpush-build -- env HOME="$src" v=$v sum=$sum sh -eu <<'E'
cd "$HOME"
[ -x .cargo/bin/cargo ] ||
  curl --proto '=https' --tlsv1.2 -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
curl -fsSL -o relay.crate "https://static.crates.io/crates/iroh-relay/iroh-relay-$v.crate"
echo "$sum  relay.crate" | sha256sum -c -
tar xzf relay.crate
cd "iroh-relay-$v"
cp ../iroh-relay.Cargo.lock Cargo.lock
for p in ping pq unlimited hold; do patch -sp1 < "../relay-$p.patch"; done
"$HOME/.cargo/bin/cargo" build -q --release --locked --features server,tls-aws-lc-rs --bin iroh-relay
E
install -m755 "$src/iroh-relay-$v/target/release/iroh-relay" /usr/local/bin/irpush-relay

umask 022   # the service's own user reads its config (no secrets in it)
cat > /etc/irpush-relay.toml <<E
http_bind_addr = "0.0.0.0:80"
enable_quic_addr_discovery = true
enable_metrics = false
[tls]
https_bind_addr = "0.0.0.0:443"
quic_bind_addr = "0.0.0.0:7842"
hostname = "$dom"
cert_mode = "LetsEncrypt"
contact = "$mail"
cert_dir = "/var/lib/irpush-relay"
[limits.client.rx]
bytes_per_second = 4194304
max_burst_bytes = 16777216
E

cat > /etc/systemd/system/irpush-relay.service <<'E'
[Unit]
After=network-online.target
Wants=network-online.target
[Service]
DynamicUser=yes
StateDirectory=irpush-relay
StateDirectoryMode=0700
Environment=RUST_LOG=warn RELAY_KEYS=/var/lib/irpush-relay/keys
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryMax=75%
ExecStart=/usr/local/bin/irpush-relay --config-path /etc/irpush-relay.toml
Restart=always
LimitNOFILE=16384
[Install]
WantedBy=multi-user.target
E

# The old relay, whatever its unit's name: stopped, so this one takes :443.
for u in $(systemctl list-units --type=service --no-legend --plain |
  awk '{print $1}'); do
  if [ "$u" != irpush-relay.service ] &&
    systemctl cat "$u" 2>/dev/null | grep -q '^ExecStart=.*iroh-relay'; then
    systemctl disable --now "$u"
    echo "stopped $u"
  fi
done
if command -v ufw >/dev/null; then
  ufw allow 80,443/tcp
  ufw allow 7842/udp
fi

systemctl daemon-reload
systemctl enable --now irpush-relay
systemctl restart irpush-relay
sleep 20
if curl -fsS "https://$dom/ping" >/dev/null; then
  echo "https://$dom is up, open to all. A key that lifts its rate limit:"
  echo "  k=/var/lib/private/irpush-relay/keys; openssl rand -hex 32 >> \$k;" \
    "chown --reference=\${k%/*} \$k; tail -1 \$k"
else
  journalctl -u irpush-relay -n 20 --no-pager
  ss -ltnp 'sport = :443'
  exit 1
fi
