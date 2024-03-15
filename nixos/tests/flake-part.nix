{
  self,
  inputs,
  ...
}: {
  perSystem = {
    config,
    pkgs,
    final,
    system,
    ...
  }: {
    checks = let
      nixos-lib = import "${inputs.nixpkgs}/nixos/lib" {};
    in
      if ! pkgs.lib.hasSuffix "linux" system
      then {}
      else {
        hoopsnake-starts = nixos-lib.runTest {
          name = "hoopsnake-starts";
          hostPkgs = pkgs;
          nodes = {
            alice = {...}: {
              environment.systemPackages = [pkgs.hello];
              imports = [
                self.nixosModules.default
              ];
            };
            bob = {};
          };

          testScript = ''
          '';
        };
      };
  };
}
