{
  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} ({
      flake-parts-lib,
      self,
      withSystem,
      ...
    }: {
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
          hoopsnake = pkgs.buildGo123Module rec {
            pname = "hoopsnake";
            version = "0.0.0";
            vendorHash = builtins.readFile ./default.sri;
            subPackages = ["cmd/hoopsnake"];
            src = lib.sourceFilesBySuffices (lib.sources.cleanSource ./.) [".go" ".mod" ".sum"];
            env.CGO_ENABLED = 0;
            meta.mainProgram = "hoopsnake";
          };
        };

        devshells.default = {
          commands = [
          ];
          packages = [
            pkgs.go_1_23
            pkgs.golangci-lint
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
