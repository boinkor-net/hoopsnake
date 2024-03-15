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
  }: let
    tls-cert = pkgs.runCommand "selfSignedCerts" {buildInputs = [pkgs.openssl];} ''
      openssl req \
        -x509 -newkey rsa:4096 -sha256 -days 365 \
        -nodes -out cert.pem -keyout key.pem \
        -subj '/CN=headscale' -addext "subjectAltName=DNS:headscale"

      mkdir -p $out
      cp key.pem cert.pem $out
    '';

    # OK, so this is pretty lol/lmao.  Since we need working API
    # keys to build the machines, we have to use "known" API keys
    # that the headscale server knows about; we also need those in
    # the environment file that alice's hoopsnake nixos config
    # module uses; and so: we take a known set of API keys and a DB
    # dump, adjust a few timings and import that into the running
    # headscale server.
    envFiles = {
      apiKey = pkgs.writeText "apikey-envfile" ''
        TS_API_KEY=OVehtREWXA._bTQCNek9SsZk5Jy9aIUpGWNWXo61rTh0QTg-_MUCv4
      '';
      authKey = pkgs.writeText "apikey-envfile" ''
        TS_AUTHKEY=e01aa49edded75748e17903330e3f18c25496b47360ffdec
      '';
      # Unfortunately, headscale doesn't support oauth client id/secret yet.
    };
    dbDump = pkgs.writeText "generated_keys.sql" ''
      INSERT INTO pre_auth_keys VALUES(1,'e01aa49edded75748e17903330e3f18c25496b47360ffdec',1,0,0,0,datetime(),datetime('now','+1 hour'));
        INSERT INTO api_keys VALUES(1,'OVehtREWXA',X'24326124313024436f72666574456a30774973344c3745616e697234756e2e536c6746654e71527030694448596153594968355a65374f6742513061',datetime(),datetime('now','+1 hour'),NULL);
    '';
    hostkey = pkgs.runCommand "hostkey" {buildInputs = [pkgs.openssh];} ''
      mkdir $out
      ssh-keygen -N "" -t ed25519 -f $out/hostkey
    '';
    clientKey = pkgs.runCommand "clientKey" {buildInputs = [pkgs.openssh];} ''
      mkdir $out
      ssh-keygen -N "" -t ed25519 -f $out/client
    '';
    bootloader = {
      virtualisation.useBootLoader = true;
      virtualisation.useEFIBoot = true;
      boot.loader.systemd-boot.enable = true;
      boot.loader.efi.canTouchEfiVariables = true;
      environment.systemPackages = [pkgs.efibootmgr];
    };
    stunPort = 3478;
    headscale = {config, ...}: {
      environment.systemPackages = [
        (pkgs.writeShellApplication {
          name = "import-pregenerated-keys";
          runtimeInputs = [pkgs.sqlite];
          text = ''
            sqlite3 /var/lib/headscale/db.sqlite <${dbDump}
          '';
        })
        pkgs.headscale
      ];
      services.headscale = {
        enable = true;
        settings = {
          ip_prefixes = ["100.64.0.0/10"];
          derp.server = {
            enabled = true;
            region_id = 999;
            stun_listen_addr = "0.0.0.0:${toString stunPort}";
          };
        };
      };
      networking.firewall = {
        allowedTCPPorts = [443 80];
        allowedUDPPorts = [stunPort];
      };
      services.nginx = {
        enable = true;
        virtualHosts.headscale = {
          addSSL = true;
          sslCertificate = "${tls-cert}/cert.pem";
          sslCertificateKey = "${tls-cert}/key.pem";
          locations."/" = {
            proxyPass = "http://127.0.0.1:${toString config.services.headscale.port}";
            proxyWebsockets = true;
          };
        };
      };
    };
  in {
    checks =
      if ! pkgs.lib.hasSuffix "linux" system
      then {}
      else {
        hoopsnake-starts = pkgs.testers.runNixOSTest {
          name = "hoopsnake-starts";
          nodes = {
            inherit headscale;
            alice = {...}: {
              imports = [bootloader self.nixosModules.default];
              boot.initrd.hoopsnake = {
                enable = true;
                ssh = {
                  authorizedKeysFile = "${clientKey}/client.pub";
                  privateHostKey = "${hostkey}/hostkey";
                };
                tailscale = {
                  name = "alice-boot";
                  tags = ["tag:hoopsnake"];
                  environmentFile = envFiles.authKey;
                };
              };
            };
            bob = {
              services.tailscale.enable = true;
              systemd.services.tailscaled.serviceConfig.Environment = ["TS_NO_LOGS_NO_SUPPORT=true"];
              security.pki.certificateFiles = ["${tls-cert}/cert.pem"];
            };
          };

          testScript = ''
            headscale.start()
            bob.start()
            headscale.wait_for_unit("headscale")
            headscale.succeed("headscale users create alice")
            headscale.succeed("import-pregenerated-keys")

            headscale.succeed("headscale users create bob")
            authkey = headscale.succeed("headscale preauthkeys -u bob create --reusable")
            headscale.wait_for_open_port(8080)
            # alice.start()

            keys = headscale.succeed("headscale preauthkeys list -u bob")
            print(keys)
            print(authkey)

            bob.wait_for_unit("tailscaled")
            bob.succeed("ping -c 1 headscale")
            bob.succeed("tailscale up --login-server 'https://headscale' --auth-key {authkey}")
            bob.wait_until_succeeds("tailscale ping alice-boot", timeout=30)
          '';
        };
      };
  };
}
