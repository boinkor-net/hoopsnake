{
  outputs = inputs @ {flake-parts, ...}:
    flake-parts.lib.mkFlake {inherit inputs;} ({
      flake-parts-lib,
      self,
      lib,
      withSystem,
      ...
    }: {
      imports =
        [
          ./nixos/tests/flake-part.nix
        ]
        ++ lib.optional (inputs.devshell ? flakeModule) {
          imports = [inputs.devshell.flakeModule];

          perSystem = {pkgs, ...}: {
            devshells.default = {
              packages = [
                pkgs.go_1_23
                pkgs.golangci-lint
              ];
            };
          };
        }
        ++ lib.optional (inputs.generate-go-sri ? flakeModules) {
          imports = [inputs.generate-go-sri.flakeModules.default];

          perSystem.go-sri-hashes.default = {};
        };

      systems = ["x86_64-linux" "aarch64-linux" "aarch64-darwin" "x86_64-darwin"];
      perSystem = {
        config,
        pkgs,
        lib,
        ...
      }: {
        formatter = pkgs.alejandra;

        packages = {
          default = config.packages.hoopsnake;
          hoopsnake = pkgs.buildGo123Module {
            pname = "hoopsnake";
            version = "0.0.0";
            vendorHash = builtins.readFile ./default.sri;
            subPackages = ["cmd/hoopsnake"];
            src = lib.sourceFilesBySuffices (lib.sources.cleanSource ./.) [".go" ".mod" ".sum"];
            CGO_ENABLED = 0;
            meta.mainProgram = "hoopsnake";
          };
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
