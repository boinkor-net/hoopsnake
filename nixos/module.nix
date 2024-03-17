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
    boot.initrd.network.hoopsnake = let
      hoopsnake = withSystem pkgs.stdenv.targetPlatform.system ({config, ...}: config.packages.default);
    in {
      enable = mkEnableOption "Enable the hoopsnake SSH server";
      package = mkOption {
        description = "The hoopsnake package";
        type = types.package;
        default = hoopsnake;
        defaultText = lib.literalExpression "inputs.hoopsnake.packages.''${system}.default";
      };

      includeSSLBundle = mkOption {
        description = "Whether to include the SSL certificate bundle data in the initrd.";
        default = true;
        type = types.bool;
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
        shellArgs = mkOption {
          description = "Arguments to pass to the shell.";
          default = ["-l"];
          type = types.listOf types.str;
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
        tsnetVerbose = mkEnableOption "verbose logging from the tsnet package";

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
    cfg = config.boot.initrd.network.hoopsnake;
  in
    lib.mkIf cfg.enable {
      boot.initrd.network.postCommands = ''
        echo "Starting hoopsnake..."
        . /etc/hoopsnake/tailscale/environment
        export TS_AUTHKEY TS_API_KEY TS_API_CLIENT_ID TS_API_CLIENT_SECRET TS_BASE_URL

        ${lib.getExe cfg.package} -name ${lib.escapeShellArg cfg.tailscale.name} \
           -tsnetVerbose=${lib.boolToString cfg.tailscale.tsnetVerbose} \
           -tags=${lib.escapeShellArg (lib.concatStringsSep "," cfg.tailscale.tags)} \
           -deleteExisting=${lib.boolToString cfg.tailscale.cleanup.deleteExisting} \
           -maxNodeAge=${lib.escapeShellArg cfg.tailscale.cleanup.maxNodeAge} \
           -authorizedKeys=/etc/hoopsnake/ssh/authorized_keys \
           -hostKey=/etc/hoopsnake/ssh/host_key \
           ${lib.escapeShellArg cfg.ssh.shell} ${lib.escapeShellArgs cfg.ssh.shellArgs} &
      '';
      boot.initrd.secrets = lib.mkMerge [
        {
          "/etc/hoopsnake/ssh/host_key" = cfg.ssh.privateHostKey;
          "/etc/hoopsnake/ssh/authorized_keys" = cfg.ssh.authorizedKeysFile;
          "/etc/hoopsnake/tailscale/environment" = cfg.tailscale.environmentFile;
        }
        (lib.mkIf cfg.includeSSLBundle {
          "/etc/ssl/ca-bundle.crt" = config.environment.etc."ssl/certs/ca-bundle.crt".source;
          "/etc/ssl/ca-certificates.crt" = config.environment.etc."ssl/certs/ca-certificates.crt".source;
          "/etc/pki/tls/certs/ca-bundle.crt" = config.environment.etc."pki/tls/certs/ca-bundle.crt".source;
          "/etc/ssl/trust-source" = config.environment.etc."ssl/trust-source".source;
        })
      ];
    };
}
