{ pkgs? import <nixpkgs> {} }:
pkgs.mkShell {
    nativeBuildInputs = with pkgs.buildPackages; [
        mdbook
        mdbook-mermaid
    ];
    shellHook = ''
    source <(mdbook completions bash)
    '';
}

