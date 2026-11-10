{
  description = "pushir: a relay mailbox, plus its relay VPS";

  inputs = {
    # Pinned by flake.lock; `make bump` moves both.
    nixpkgs.url = "https://channels.nixos.org/nixos-26.05/nixexprs.tar.xz";
    disko = { url = "git+https://github.com/nix-community/disko"; inputs.nixpkgs.follows = "nixpkgs"; };
  };

  outputs = { self, nixpkgs, disko }:
    let
      lib = nixpkgs.lib;
      cfg = import ./deploy/config.nix;
      each = lib.genAttrs [ "x86_64-linux" "aarch64-linux" ];
      fs = lib.fileset;
      pkgsFor = system: nixpkgs.legacyPackages.${system};
      relay = pkgs: pname: patches: features: pkgs.rustPlatform.buildRustPackage {
        inherit pname patches;
        version = "1.4.1";
        src = pkgs.fetchCrate { pname = "iroh-relay"; version = "1.4.1"; hash = "sha256-FOJJwZnmXHSM8nSvWIJoD+EMPASJfFIti3/X8E+cRxw="; };
        cargoLock.lockFile = ./deploy/iroh-relay.Cargo.lock;
        buildFeatures = [ "server" ] ++ features;
        cargoBuildFlags = [ "--bin" "iroh-relay" ];
        doCheck = false;
      };
    in {
      packages = each (system: let pkgs = pkgsFor system; in {
        default = self.packages.${system}.pushir;
        pushir = pkgs.rustPlatform.buildRustPackage {
          pname = "pushir";
          version = "0.3.0";
          src = fs.toSource { root = ./.; fileset = fs.unions [ ./Cargo.toml ./Cargo.lock ./src ]; };
          cargoLock = { lockFile = ./Cargo.lock; allowBuiltinFetchGit = true; }; # irnet, by its commit
          doCheck = false;
        };
        iroh-relay = relay pkgs "iroh-relay" [ ] [ ];                                # stock: iroh data relay
        # server ping after 130 min of client silence (clients drive heartbeats); TLS by aws-lc-rs with
        # X25519MLKEM768 first, so the relay hop is post-quantum (stock iroh-relay: ring, X25519 only);
        # a key in $RELAY_KEYS lifts the rate limit (big transfers that cannot go direct); a pushir frame is
        # kept until its mailbox pongs it (64 each, 65,536 in all, a day), 64 at once then one a second
        irpush-relay = relay pkgs "irpush-relay"
          [ ./deploy/relay-ping.patch ./deploy/relay-pq.patch ./deploy/relay-unlimited.patch ./deploy/relay-hold.patch ]
          [ "tls-aws-lc-rs" ];
      });

      nixosModules.relays = import ./deploy/relays.nix self;

      nixosConfigurations.relay = lib.nixosSystem {
        inherit (cfg) system;
        modules = [ disko.nixosModules.disko self.nixosModules.relays ./deploy/host.nix ];
      };
    };
}
