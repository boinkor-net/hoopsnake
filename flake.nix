{
  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      imports = [
        inputs.generate-go-sri.flakeModules.default
      ];
      systems = [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin" ];
      perSystem = { config, pkgs, lib, ... }: {
        go-sri-hashes.default = {};

        packages = {
          default = config.packages.hoopsnake;
          hoopsnake = pkgs.buildGo122Module rec {
            pname = "hoopsnake";
            version = "0.0.0";
            vendorHash = (builtins.readFile ./default.sri);
            subPackages = ["cmd/hoopsnake"];
            src = lib.sourceFilesBySuffices (lib.sources.cleanSource ./.) [".go" ".mod" ".sum"];
            meta.mainProgram = "hoopsnake";
          };
        };
      };
    };

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devshell.url = "github:numtide/devshell";
    generate-go-sri.url = "github:antifuchs/generate-go-sri";
 };
}
