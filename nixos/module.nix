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
          description = "Path to a file listing the authorized public keys that may authenticate to hoopsnake.";
          type = types.nullOr types.path;
        };
        privateHostKey = mkOption {
          description = "Path to a PEM-encoded secret key that the hoopsnake SSH server will use to authenticate itself to clients. This is a secret - it should't live in the nix store. Only used in scripted stage1; if you use systemd in initrd, see the systemd-credentials section.";
          type = types.path;
        };
        shell = mkOption {
          description = "The shell package to run. Used to build boot.initrd.network.hoopsnake.ssh.commandLine.";
          default = "${pkgs.busybox}/bin/ash";
          type = types.oneOf [types.shellPackage types.path];
        };

        commandLine = mkOption {
          description = "The concrete commandline to run.";
          default = [config.boot.initrd.network.hoopsnake.ssh.shell];
          type = types.listOf types.str;
        };
      };

      systemd-credentials = let
        credentialSpec.options = {
          text = mkOption {
            description = "A string giving the literal credential. If encrypted, this must be base64-encoded; otherwise, escape non-printable characters with \\x00 and so on.";
            type = types.str;
          };
          file = mkOption {
            description = "The pathname where a file containing the credential lives.";
            type = types.nullOr types.path;
            default = null;
          };
          encrypted = mkOption {
            description = "Whether the credential is presented as encrypted.";
            type = types.bool;
            default = true;
          };
        };
      in {
        privateHostKey = mkOption {
          description = "systemd credential spec for the SSH private host key.";
          type = types.submodule credentialSpec;
        };
        clientId = mkOption {
          description = "systemd credential spec for the tailscale OpenID2 client ID.";
          type = types.submodule credentialSpec;
        };
        clientSecret = mkOption {
          description = "systemd credential spec for the tailscale OpenID2 client secret.";
          type = types.submodule credentialSpec;
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
          description = "Environment file setting TS_AUTHKEY, TS_API_KEY or TS_API_CLIENT_ID & TS_API_CLIENT_SECRET. These are secrets, so shouldn't live in the nix store. Only used in scripted stage1; If you use systemd in initrd, see the systemd-credentials section.";
          type = types.nullOr types.path;
          default = null;
        };
        tsnetVerbose = mkEnableOption "verbose logging from the tsnet package";

        cleanup = {
          exitTimeoutSec = mkOption {
            description = "Number of seconds to wait for hoopsnake to exit after boot continues. If set to null, do not wait.";
            default = 5;
            type = types.nullOr types.int;
          };
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
    lib.mkIf cfg.enable (lib.mkMerge [
      (lib.mkIf (!config.boot.initrd.systemd.enable) {
        # Scripted stage1 (sans systemd-in-initrd):
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
             ${lib.escapeShellArgs cfg.ssh.commandLine} &
          hoopsnakePid=$!
        '';
        boot.initrd.postMountCommands = ''
            if [ -n "$hoopsnakePid" ]; then
            kill "$hoopsnakePid"
            ${
            if cfg.tailscale.cleanup.exitTimeoutSec != null
            then ''
              timeToWait=${toString cfg.tailscale.cleanup.exitTimeoutSec}
              while [ $timeToWait -gt 0 ] && ! kill -0 "$hoopsnakePid" 2>/dev/null ; do
                timeToWait=$((timeToWait-1))
                sleep 1
              done
            ''
            else ""
          }
          fi
        '';
        boot.initrd.secrets = lib.mkMerge [
          {
            "/etc/hoopsnake/ssh/host_key" = cfg.ssh.privateHostKey;
            "/etc/hoopsnake/ssh/authorized_keys" = cfg.ssh.authorizedKeysFile;
          }
          (lib.mkIf (cfg.tailscale.environmentFile != null) {"/etc/hoopsnake/tailscale/environment" = cfg.tailscale.environmentFile;})
          (lib.mkIf cfg.includeSSLBundle {
            "/etc/ssl/ca-bundle.crt" = config.environment.etc."ssl/certs/ca-bundle.crt".source;
            "/etc/ssl/ca-certificates.crt" = config.environment.etc."ssl/certs/ca-certificates.crt".source;
            "/etc/pki/tls/certs/ca-bundle.crt" = config.environment.etc."pki/tls/certs/ca-bundle.crt".source;
            "/etc/ssl/trust-source" = config.environment.etc."ssl/trust-source".source;
          })
        ];
      })
      (lib.mkIf config.boot.initrd.systemd.enable (let
        credentials = ["privateHostKey" "clientId" "clientSecret"];
        textCredentials =
          lib.concatMap (
            credName:
              if (cfg.systemd-credentials.${credName}.file == null)
              then [credName]
              else []
          )
          credentials;
        fileCredentials =
          lib.concatMap (
            credName:
              if (cfg.systemd-credentials.${credName}.file != null)
              then [credName]
              else []
          )
          credentials;
      in {
        boot.initrd.systemd.storePaths = [cfg.package cfg.ssh.shell];
        boot.initrd.systemd.services.hoopsnake = {
          description = "Hoopsnake initrd ssh server";
          wantedBy = ["initrd.target"];
          after = ["network.target" "initrd-nixos-copy-secrets.service"];
          before = ["shutdown.target" "initrd-switch-root.target"];
          conflicts = ["shutdown.target" "initrd-switch-root.target"];

          script = ''
            set -eu -x

            exec ${lib.getExe cfg.package} -name ${lib.escapeShellArg cfg.tailscale.name} \
              -tsnetVerbose=${lib.boolToString cfg.tailscale.tsnetVerbose} \
              -tags=${lib.escapeShellArg (lib.concatStringsSep "," cfg.tailscale.tags)} \
              -deleteExisting=${lib.boolToString cfg.tailscale.cleanup.deleteExisting} \
              -maxNodeAge=${lib.escapeShellArg cfg.tailscale.cleanup.maxNodeAge} \
              -authorizedKeys=/etc/hoopsnake/ssh/authorized_keys \
              -hostKey=''${CREDENTIALS_DIRECTORY}/privateHostKey \
              -clientIdFile=''${CREDENTIALS_DIRECTORY}/clientId \
              -clientSecretFile=''${CREDENTIALS_DIRECTORY}/clientSecret \
              ${lib.escapeShellArg cfg.ssh.commandLine}
          '';

          environment.HOME = "/tmp";
          serviceConfig = {
            Type = "simple";
            KillMode = "process";
            Restart = "on-failure";
            EnvironmentFile = lib.mkIf (cfg.tailscale.environmentFile != null) "/etc/hoopsnake/tailscale/environment";
            LoadCredential =
              lib.concatMap (
                credName:
                  if (!cfg.systemd-credentials.${credName}.encrypted)
                  then ["${credName}:/etc/hoopsnake/${credName}"]
                  else []
              )
              fileCredentials;
            LoadCredentialEncrypted =
              lib.concatMap (
                credName:
                  if cfg.systemd-credentials.${credName}.encrypted
                  then ["${credName}:/etc/hoopsnake/${credName}"]
                  else []
              )
              fileCredentials;

            SetCredential =
              lib.concatMap (
                credName:
                  if (!cfg.systemd-credentials.${credName}.encrypted)
                  then ["${credName}:${cfg.systemd-credentials.${credName}.text}"]
                  else []
              )
              textCredentials;
            SetCredentialEncrypted =
              lib.concatMap (
                credName:
                  if cfg.systemd-credentials.${credName}.encrypted
                  then ["${credName}:${cfg.systemd-credentials.${credName}.text}"]
                  else []
              )
              textCredentials;
          };
        };
        boot.initrd.secrets = lib.mkMerge [
          {
            "/etc/hoopsnake/ssh/authorized_keys" = cfg.ssh.authorizedKeysFile;
          }
          (lib.mkIf (cfg.tailscale.environmentFile != null) {"/etc/hoopsnake/tailscale/environment" = cfg.tailscale.environmentFile;})
          (lib.mkIf cfg.includeSSLBundle {
            "/etc/ssl/ca-bundle.crt" = config.environment.etc."ssl/certs/ca-bundle.crt".source;
            "/etc/ssl/ca-certificates.crt" = config.environment.etc."ssl/certs/ca-certificates.crt".source;
            "/etc/pki/tls/certs/ca-bundle.crt" = config.environment.etc."pki/tls/certs/ca-bundle.crt".source;
            "/etc/ssl/trust-source" = config.environment.etc."ssl/trust-source".source;
          })
          (builtins.listToAttrs (builtins.map (credName: {
              name = "/etc/hoopsnake/${credName}";
              value = "${cfg.systemd-credentials.${credName}.file}";
            })
            fileCredentials))
        ];
      }))
    ]);
}
