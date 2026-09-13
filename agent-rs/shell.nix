{ pkgs ? import <nixpkgs> {} }:
pkgs.mkShell {
  buildInputs = with pkgs; [
    rustc cargo pkg-config openssl
    # untuk musl static: pkgs.pkgsStatic.stdenv.cc
  ];
  RUST_SRC_PATH = "${pkgs.rustPlatform.rustLibSrc}";
}
