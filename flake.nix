{
  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} ({
      flake-parts-lib,
      self,
      withSystem,
      ...
    }: let
      inherit (flake-parts-lib) importApply;
    in {
      imports = [
        inputs.devshell.flakeModule
        inputs.generate-go-sri.flakeModules.default
        ./nixos/tests/flake-part.nix
      ];
      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin"];
      perSystem = {
        config,
        pkgs,
        lib,
        ...
      }: {
        formatter = pkgs.alejandra;
        go-sri-hashes.default = {};

        packages = {
          default = config.packages.hoopsnake;
          hoopsnake = pkgs.buildGo122Module rec {
            pname = "hoopsnake";
            version = "0.0.0";
            vendorHash = builtins.readFile ./default.sri;
            subPackages = ["cmd/hoopsnake"];
            src = lib.sourceFilesBySuffices (lib.sources.cleanSource ./.) [".go" ".mod" ".sum"];
            meta.mainProgram = "hoopsnake";
          };
        };

        devshells.default = {
          commands = [
          ];
          packages = [
            pkgs.go_1_22
            pkgs.gopls
            (pkgs.golangci-lint.override
              {buildGoModule = args: (pkgs.buildGo122Module args);})
          ];
        };
      };

      flake.nixosModules.default = import ./nixos/module.nix {
        inherit withSystem;
      };
    });

  inputs = {
    flake-parts.url = "github:hercules-ci/flake-parts";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    devshell.url = "github:numtide/devshell";
    generate-go-sri.url = "github:antifuchs/generate-go-sri";
  };
}
