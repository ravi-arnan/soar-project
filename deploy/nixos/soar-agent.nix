# Modul NixOS untuk soar-agent (agen ringan SOAR, alternatif Wazuh Agent).
#
# Kenapa modul, bukan .deb seperti workstation lain:
#   - NixOS tidak punya dpkg, dan /usr/local tidak dikelola deklaratif.
#   - Binary prebuilt di repo ter-link ke glibc /nix/store (bukan musl), jadi bisa
#     rusak kena `nix-collect-garbage`. Dengan buildRustPackage, seluruh
#     dependency runtime masuk closure sistem dan ikut ter-rebuild.
#
# Pakai di /etc/nixos/configuration.nix:
#
#   imports = [ /home/ravi/Projects/soar-project/deploy/nixos/soar-agent.nix ];
#
#   services.soar-agent = {
#     enable = true;
#     agentId = "002";
#     agentName = "nixbox";
#     server = "192.168.1.47";   # LAN ravi-debian (Tailscale 100.x sedang tidak routable dari nixbox)
#     packageSource = /home/ravi/Projects/soar-project/agent-rs;
#   };
#
# Lalu: sudo nixos-rebuild switch --flake /etc/nixos#nixbox

{ config, lib, pkgs, ... }:

let
  cfg = config.services.soar-agent;

  soar-agent = pkgs.rustPlatform.buildRustPackage {
    pname = "soar-agent";
    version = "0.1.0";
    src = cfg.packageSource;
    cargoLock.lockFile = cfg.packageSource + "/Cargo.lock";
    nativeBuildInputs = [ pkgs.pkg-config ];
    # butuh network untuk test integrasi; binernya sendiri tidak butuh test.
    doCheck = false;
    meta = {
      description = "Agen ringan SOAR Rust - pantau file, hitung hash, POST ke n8n";
      license = lib.licenses.gpl2Only;
      mainProgram = "soar-agent";
    };
  };

  args = [
    "${soar-agent}/bin/soar-agent"
    "--webhook" "http://${cfg.server}:${toString cfg.n8nPort}/webhook/wazuh-alert"
    "--agent-id" cfg.agentId
    "--agent-name" cfg.agentName
    "--fleet-url" "http://${cfg.server}:${toString cfg.fleetPort}/api/heartbeat"
    "--heartbeat-secs" (toString cfg.heartbeatSecs)
    "--listen-port" (toString cfg.listenPort)
  ] ++ lib.optional (cfg.watch != [ ]) "--watch" ++ lib.optional (cfg.watch != [ ]) (lib.concatStringsSep "," cfg.watch);
in
{
  options.services.soar-agent = {
    enable = lib.mkEnableOption "SOAR agen ringan Rust (alternatif Wazuh Agent)";

    packageSource = lib.mkOption {
      type = lib.types.path;
      example = /home/ravi/Projects/soar-project/agent-rs;
      description = "Direktori sumber agent-rs (berisi Cargo.toml + Cargo.lock).";
    };

    agentId = lib.mkOption {
      type = lib.types.str;
      default = "002";
      description = "ID unik agent, muncul di Fleet Monitor & callback HITL.";
    };

    agentName = lib.mkOption {
      type = lib.types.str;
      default = "nixbox";
      description = "Nama agent yang tampil di dashboard.";
    };

    server = lib.mkOption {
      type = lib.types.str;
      default = "192.168.1.47";
      description = "Alamat server SOAR (host yang menjalankan n8n + fleet-monitor).";
    };

    n8nPort = lib.mkOption {
      type = lib.types.port;
      default = 5678;
      description = "Port n8n (webhook wazuh-alert).";
    };

    fleetPort = lib.mkOption {
      type = lib.types.port;
      default = 8080;
      description = "Port fleet-monitor (endpoint /api/heartbeat).";
    };

    heartbeatSecs = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "Interval heartbeat ke Fleet Monitor (detik).";
    };

    listenPort = lib.mkOption {
      type = lib.types.port;
      default = 8787;
      description = "Port lokal untuk endpoint /quarantine.";
    };

    watch = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Path tambahan yang dipantau (dipisah koma saat diteruskan ke binary).
        Kosong = pakai default binary: $HOME/Downloads + $HOME/Desktop.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "ravi";
      description = ''
        User yang menjalankan agent. Harus user pemilik file yang dipantau,
        karena default watch path diturunkan dari $HOME.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    systemd.services.soar-agent = {
      description = "SOAR Agen Ringan Rust (alternatif Wazuh Agent)";
      after = [ "network-online.target" ];
      wants = [ "network-online.target" ];
      wantedBy = [ "multi-user.target" ];

      environment = {
        RUST_LOG = "info";
        HOME = config.users.users.${cfg.user}.home;
      };

      serviceConfig = {
        Type = "simple";
        User = cfg.user;
        Group = config.users.users.${cfg.user}.group;
        # Argumen dibangun di Nix, bukan lewat EnvironmentFile, supaya seluruh
        # konfigurasi deklaratif di satu tempat (cara NixOS).
        ExecStart = lib.concatStringsSep " " args;
        Restart = "always";
        RestartSec = 5;
        NoNewPrivileges = true;
        # Karantina bisa jatuh ke /var/ossec/quarantine atau /tmp/soar-quarantine,
        # jadi TIDAK pakai PrivateTmp supaya hasilnya tetap terlihat dari luar.
        ProtectHome = false; # perlu baca ~/Downloads & ~/Desktop
      };
    };
  };
}
