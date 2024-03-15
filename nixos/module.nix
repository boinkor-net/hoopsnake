# importApply arguments:
{withSystem}:
# Regular NixOS module arguments:
{
  lib,
  pkgs,
  config,
  ...
}: {
  options = with lib; {
    boot.initrd.hoopsnake = let
      flakePkgs = withSystem ({config, ...}: config.packages);
    in {
      enable = mkEnableOption "Enable the hoopsnake SSH server";
      package = mkPackageOption flakePkgs "hoopsnake" {
        default = ["inputs.hoopsnake.packages.default"];
      };

      ssh = {
        authorizedKeysFile = mkOption {
          description = "Path to a file listing the authorized public keys that may authenticate to hoopsnake";
          type = types.nullOr types.path;
        };
        privateHostKey = mkOption {
          description = "Path to a PEM-encoded secret key that the hoopsnake SSH server will use to authenticate itself to clients. This is a secret - it should't live in the nix store.";
          type = types.path;
        };
        shell = mkOption {
          description = "The shell package to run";
          default = "${pkgs.busybox}/bin/ash";
          type = types.oneOf [types.shellPackage types.path];
        };
      };

      tailscale = {
        name = mkOption {
          description = "Name of the tailscale service that the hoopsnake SSH server runs on.";
          type = types.str;
        };
        tags = mkOption {
          description = "List of tags to assign the hoopsnake SSH server. At least one is required.";
          type = types.nonEmptyListOf (types.strMatching "^tag:.+$");
        };
        environmentFile = mkOption {
          description = "Environment file setting TS_AUTHKEY, TS_API_KEY or TS_API_CLIENT_ID & TS_API_CLIENT_SECRET. These are secrets, so shouldn't live in the nix store.";
          type = types.path;
        };
        cleanup = {
          deleteExisting = mkOption {
            description = "Whether to delete existing nodes with the configured hoopsnake SSH server's name";
            default = false;
            type = types.bool;
          };

          maxNodeAge = mkOption {
            description = "Any existing node with this server's name must be offline at least this long to be considered for deletion.";
            default = "30s";
            type = types.str;
          };
        };
      };
    };
  };

  config = let
    cfg = config.boot.initrd.hoopsnake;
  in
    lib.mkIf cfg.enable {
      boot.initrd.network.postCommands = ''
        . /etc/hoopsnake/tailscale/environment
        export TS_AUTHKEY TS_API_KEY TS_API_CLIENT_ID TS_API_CLIENT_SECRET TS_BASE_URL

        ${lib.getExe cfg.package} -name ${lib.escapeShellArg cfg.tailscale.name} \
           -tags=${lib.escapeShellArg (lib.concatStringsSep cfg.tailscale.tags ",")} \
           -deleteExisting=${lib.boolToString cfg.tailscale.cleanup.deleteExisting} \
           -maxNodeAge=${lib.escapeShellArg cfg.tailscale.cleanup.maxNodeAge} \
           -authorizedKeys=/etc/hoopsnake/ssh/authorized_keys \
           -hostKey=/etc/hoopsnake/ssh/host_key \
           ${lib.escapeShellArg cfg.ssh.shell} &
      '';
      boot.initrd.secrets = {
        "/etc/hoopsnake/ssh/host_key" = cfg.ssh.privateHostKey;
        "/etc/hoopsnake/ssh/authorized_keys" = cfg.ssh.authorizedKeysFile;
        "/etc/hoopsnake/tailscale/environment" = cfg.tailscale.environmentFile;
      };
    };
}
