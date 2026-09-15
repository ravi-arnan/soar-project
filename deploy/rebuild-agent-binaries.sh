#!/usr/bin/env bash
# =============================================================================
# rebuild-agent-binaries.sh — build ulang soar-agent pasca-fix IP/OS
# Dijalankan DI ravi-debian (punya cargo cache + mingw linker).
#   ./rebuild-agent-binaries.sh            : fix 003 (linux gnu) saja
#   ./rebuild-agent-binaries.sh --windows  : + cross-compile soar-agent.exe
#   ./rebuild-agent-binaries.sh --deb      : + bungkus .deb buat 100 PC
#
# Butuh sudo (install binary, apt rustup, systemctl). Shebang idempoten:
# langkah yang sudah beres di-skip otomatis, aman di-run ulang.
# =============================================================================
set -euo pipefail

cd "$(dirname "$0")/../agent-rs"
WITH_WINDOWS=0
WITH_DEB=0
for a in "$@"; do
  case "$a" in
    --windows) WITH_WINDOWS=1 ;;
    --deb) WITH_DEB=1 ;;
    *) echo "[x] flag tidak dikenal: $a (pakai --windows / --deb)"; exit 1 ;;
  esac
done

echo "[1/4] build linux (gnu, registry cache lokal)"
# ponytail: cargo distro (1.85) TERLALU TUA untuk Cargo.lock (icu_provider
# butuh 1.88+) -> pakai rustup stable kalau ada. Binary HARUS build di sini
# (glibc Debian 2.41); binary dari nixbox (glibc 2.42, interpreter /nix/store)
# tidak bisa jalan di Debian (status=203/EXEC). Sudah kejadian 14 Sep.
if command -v rustup >/dev/null 2>&1 && rustup toolchain list 2>/dev/null | grep -q stable; then
  export PATH="$HOME/.cargo/bin:$PATH"
  rustup run stable cargo build --release
else
  cargo build --release
fi
BIN="target/release/soar-agent"
strip "$BIN" 2>/dev/null || true
ls -la "$BIN"

echo "[2/4] pasang ke /usr/local/bin + restart (agent 003 ravi-debian)"
sudo install -m755 "$BIN" /usr/local/bin/soar-agent
sudo systemctl restart soar-agent
sleep 2
systemctl is-active soar-agent
echo "cek: curl -s http://127.0.0.1:8080/api/fleet | grep -o '003[^}]*'"

if [ "$WITH_WINDOWS" = "1" ]; then
  echo "[3/4] cross-compile windows .exe (butuh rustup + std windows-gnu, sekali saja)"
  if ! command -v rustup >/dev/null 2>&1; then
    sudo apt-get install -y rustup
  fi
  # rustup toolchain terpisah dari cargo distro; pin stable biar reproduksibel
  if ! rustup target list --installed 2>/dev/null | grep -q x86_64-pc-windows-gnu; then
    rustup toolchain install stable --target x86_64-pc-windows-gnu --profile minimal
  fi
  export CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER=x86_64-w64-mingw32-gcc
  # ponytail: rust >= 1.83 link -l:libpthread.a; mingw-w64 >= 12 tidak bundle
  # winpthreads -> tambah -L dari nixpkgs pkgsCross.mingwW64.windows.pthreads.
  # (Di nixbox path-nya di bawah; di Debian apt mingw sudah include pthread.)
  for p in /nix/store/*mingw_w64-pthreads-*/lib; do
    [ -f "$p/libpthread.a" ] && export RUSTFLAGS="-L $p" && break
  done
  rustup run stable cargo build --release --target x86_64-pc-windows-gnu --manifest-path "$PWD/Cargo.toml"
  EXE="target/x86_64-pc-windows-gnu/release/soar-agent.exe"
  [ -f "$EXE" ] || { echo "[x] exe tidak jadi: $EXE"; exit 1; }
  x86_64-w64-mingw32-strip "$EXE" 2>/dev/null || true
  install -m644 "$EXE" ../deploy/bundle/soar-agent.exe
  ls -la ../deploy/bundle/soar-agent.exe
  echo "lanjut: jalankan ulang install-agent-windows.ps1 di 005/006"
fi

if [ "$WITH_DEB" = "1" ]; then
  echo "[4/4] bungkus .deb (binary gnu, bukan musl: std musl tidak ada di toolchain ini)"
  # ponytail: musl di-skip, glibc gnu cukup untuk fleet Debian/Ubuntu.
  # Upgrade path: pasang rustup + target musl kalau perlu statis penuh.
  BIN="$PWD/target/release/soar-agent" ./build-deb.sh
fi

echo "selesai."
