{ pkgs? import <nixpkgs> {} }:
pkgs.mkShell {
    nativeBuildInputs = with pkgs.buildPackages; [
        mdbook
        mdbook-admonish
        mdbook-mermaid
    ];
    shellHook = ''
    source <(mdbook completions bash)
    '';
}

