# Relay VPS (optional). Edit deploy/config.nix, point both DNS names at the VPS, then:
#   make deploy HOST=1.2.3.4   # first time: installs NixOS over a fresh Ubuntu/Debian VPS (wipes it)
#   make update HOST=...       # apply config changes
#   make key HOST=...          # a new key that lifts the relay's rate limit (`make keys`: all of them)
HOST ?=
SSH := ssh root@$(HOST)

build:
	cargo build --release

deploy:
	nix run github:nix-community/nixos-anywhere -- --build-on remote --flake .#relay root@$(HOST)

update:
	nix run nixpkgs#nixos-rebuild -- switch --flake .#relay --target-host root@$(HOST) --build-host root@$(HOST)

key:
	$(SSH) 'umask 077; d=/var/lib/private/irpush-relay; openssl rand -hex 32 >> $$d/keys && chown --reference=$$d $$d/keys && tail -1 $$d/keys'

keys:
	$(SSH) cat /var/lib/private/irpush-relay/keys

bump:
	nix flake update

# Every test against the relay as deployed (iroh-relay with deploy/'s patches): the two that need it too.
relay-test:
	rm -rf target/relay && mkdir -p target/relay/pushir
	curl -fsSL https://static.crates.io/crates/iroh-relay/iroh-relay-1.4.1.crate | tar xz -C target/relay
	cp deploy/iroh-relay.Cargo.lock target/relay/iroh-relay-1.4.1/Cargo.lock
	for p in ping pq unlimited hold; do patch -sp1 -d target/relay/iroh-relay-1.4.1 < deploy/relay-$$p.patch || exit 1; done
	cp -r Cargo.toml Cargo.lock src tests target/relay/pushir
	cd target/relay/pushir && cargo test --config 'patch.crates-io.iroh-relay.path="../iroh-relay-1.4.1"' -- --include-ignored

.PHONY: build deploy update key keys bump relay-test
