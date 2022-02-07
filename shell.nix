with import <nixpkgs> {};

let src = fetchFromGitHub {
      owner = "mozilla";
      repo = "nixpkgs-mozilla";
      rev = "8c007b60731c07dd7a052cce508de3bb1ae849b4";
      hash = "sha256-RsNPnEKd7BcogwkqhaV5kI/HuNC4flH/OQCC/4W5y/8=";
   };
in
with import "${src.out}/rust-overlay.nix" pkgs pkgs;

stdenv.mkDerivation {
  name = "rust-pijul";
  buildInputs = [ rustChannels.stable.rust libsodium pkgconfig openssl ];
}
