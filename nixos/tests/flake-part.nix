{self, ...}: {
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
        TS_BASE_URL=https://headscale
      '';
      authKey = pkgs.writeText "apikey-envfile" ''
        TS_AUTHKEY=e01aa49edded75748e17903330e3f18c25496b47360ffdec
        TS_BASE_URL=https://headscale
      '';
      # Unfortunately, headscale doesn't support oauth client id/secret yet.
    };
    dbDump = pkgs.writeText "generated_keys.sql" ''
      .timeout 5000
      INSERT INTO pre_auth_keys VALUES(90,'e01aa49edded75748e17903330e3f18c25496b47360ffdec',1,0,0,0,datetime(),datetime('now','+1 hour'));
      INSERT INTO api_keys VALUES(90,'OVehtREWXA',X'24326124313024436f72666574456a30774973344c3745616e697234756e2e536c6746654e71527030694448596153594968355a65374f6742513061',datetime(),datetime('now','+1 hour'),NULL);
    '';
    hostkey = pkgs.runCommand "hostkey" {buildInputs = [pkgs.openssh];} ''
      mkdir $out
      ssh-keygen -N "" -t ed25519 -f $out/hostkey
      (echo -n 'alice-boot ' ; cat $out/hostkey.pub) > $out/known_hosts
    '';
    clientKey = pkgs.runCommand "clientKey" {buildInputs = [pkgs.openssh];} ''
      mkdir $out
      ssh-keygen -N "" -t ed25519 -f $out/client
    '';
    badClientKey = pkgs.runCommand "badClientKey" {buildInputs = [pkgs.openssh];} ''
      mkdir $out
      ssh-keygen -N "" -t ed25519 -f $out/client
    '';
    bootloader = {config, ...}: {
      virtualisation.useBootLoader = true;
      virtualisation.useEFIBoot = true;
      virtualisation.cores = 4;
      virtualisation.memorySize = 1024;
      boot.loader.systemd-boot.enable = true;
      boot.loader.efi.canTouchEfiVariables = true;
      environment.systemPackages = [pkgs.efibootmgr];
      boot.kernelParams = [
        "ip=${config.networking.primaryIPAddress}:::255.255.255.0::eth1:off"
      ];
      boot.initrd.network = {
        enable = true;
        udhcpc.enable = false;
      };
      boot.initrd.secrets = {
        "/etc/hosts" = "${config.environment.etc.hosts.source}";
      };
      security.pki.certificateFiles = ["${tls-cert}/cert.pem"];
    };
    headscalePort = 8080;
    stunPort = 3478;

    headscale = {config, ...}: {
      services = {
        headscale = {
          enable = true;
          port = headscalePort;
          settings = {
            server_url = "https://headscale";
            ip_prefixes = ["100.64.0.0/10"];
            dns.base_domain = "hoopsnake-testing.example.com";
            derp.server = {
              enabled = true;
              region_id = 999;
              stun_listen_addr = "0.0.0.0:${toString stunPort}";
            };
          };
        };
        nginx = {
          enable = true;
          virtualHosts.headscale = {
            addSSL = true;
            sslCertificate = "${tls-cert}/cert.pem";
            sslCertificateKey = "${tls-cert}/key.pem";
            locations."/" = {
              proxyPass = "http://127.0.0.1:${toString headscalePort}";
              proxyWebsockets = true;
            };
          };
        };
      };
      networking.firewall = {
        allowedTCPPorts = [80 443];
        allowedUDPPorts = [stunPort];
      };
      environment.systemPackages = [
        pkgs.headscale
        (pkgs.writeShellApplication {
          name = "import-pregenerated-keys";
          runtimeInputs = [pkgs.sqlite];
          text = ''
            sqlite3 /var/lib/headscale/db.sqlite <${dbDump}
          '';
        })
      ];
    };
    bob = {
      services.tailscale.enable = true;
      security.pki.certificateFiles = ["${tls-cert}/cert.pem"];
      networking.useDHCP = false;
      environment.etc.sshKey = {
        source = "${clientKey}/client";
        mode = "0600";
      };
      environment.systemPackages = [
        (pkgs.writeShellApplication {
          name = "ssh-to-alice";
          runtimeInputs = [pkgs.openssh];
          text = ''
            echo "${hostkey} fingerprint:" >&2
            ssh-keygen -l -f ${hostkey}/hostkey
            echo "${hostkey} contents:" >&2
            cat ${hostkey}/hostkey >&2
            echo "${hostkey}/known_hosts file contents:" >&2
            cat ${hostkey}/known_hosts >&2
            echo | ssh -v -o UserKnownHostsFile=${hostkey}/known_hosts -i /etc/sshKey shell@alice-boot
          '';
        })
      ];
    };
    mallory = pkgs.lib.mkMerge [
      bob
      {
        environment.etc.badSshKey = {
          source = "${badClientKey}/client";
          mode = "0600";
        };
        environment.etc.spoofedPubkey = {
          source = "${clientKey}/client.pub";
          mode = "0600";
        };
        environment.systemPackages = let
          poc = pkgs.buildGoModule {
            pname = "CVE-2024-45337";
            version = "0.0.1";
            src = pkgs.fetchgit {
              url = "https://codeberg.org/Gusted/CVE-2024-45337.git";
              rev = "9d021bfa1898c53929c5a6ef70e03b80a1a2fd52";
              hash = "sha256-B7Qpxs6+gpVwJULlYbCPcaVjAksA+XGBj52wV9sGsK8=";
            };
            vendorHash = null;
            meta.mainProgram = "CVE-2024-45337";
          };
        in [
          (pkgs.writeShellApplication {
            name = "ssh-to-alice-but-evil";
            text = ''
              ${pkgs.lib.getExe poc} -i /etc/badSshKey -s "$(cat /etc/spoofedPubkey)" shell@alice-boot
            '';
          })
        ];
      }
    ];
  in {
    checks =
      if ! pkgs.lib.hasSuffix "linux" system
      then {}
      else {
        hoopsnake-scripted = pkgs.testers.runNixOSTest {
          name = "hoopsnake-scripted-initrd-stage1";
          nodes = {
            inherit headscale bob;
            alice = {
              lib,
              config,
              ...
            }: {
              imports = [bootloader self.nixosModules.default];
              boot.initrd.preLVMCommands = ''
                while ! [ -f /tmp/fnord ] ; do
                  sleep 1
                done
              '';

              boot.initrd.network = {
                hoopsnake = {
                  enable = true;
                  ssh = {
                    authorizedKeysFile = "${clientKey}/client.pub";
                    privateHostKey = "${hostkey}/hostkey";
                    shell = lib.getExe (pkgs.writeShellApplication {
                      name = "success";
                      text = "touch /tmp/fnord";
                    });
                  };
                  tailscale = {
                    name = "alice-boot";
                    tags = ["tag:hoopsnake"];
                    environmentFile = envFiles.authKey;
                    tsnetVerbose = true;
                  };
                };
              };
            };
          };

          testScript = ''
            with subtest("Test setup"):
                for node in [headscale, bob]:
                    node.start()
                headscale.wait_for_unit("headscale")
                headscale.wait_for_open_port(443)

                # Create headscale user and preauth-key
                headscale.succeed("headscale users create bob")
                authkey = headscale.succeed("headscale preauthkeys -u bob create --reusable")

                # Connect peers
                up_cmd = f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
                bob.execute(up_cmd)
                headscale.succeed("import-pregenerated-keys")

            alice.start()
            bob.wait_until_succeeds("tailscale ping alice-boot", timeout=30)
            bob.succeed("ssh-to-alice", timeout=90)
            alice.wait_for_unit("multi-user.target", timeout=90)
          '';
        };
        hoopsnake-systemd = pkgs.testers.runNixOSTest {
          name = "hoopsnake-systemd-initrd-stage1";
          nodes = {
            inherit headscale bob;
            alice = {
              lib,
              config,
              ...
            }: let
              fakeShell = pkgs.writeShellApplication {
                name = "success";
                text = "touch /tmp/fnord";
              };
            in {
              imports = [bootloader self.nixosModules.default];
              testing.initrdBackdoor = true;
              boot.initrd.systemd = {
                enable = true;
                initrdBin = [fakeShell];
              };
              boot.initrd.network.hoopsnake = {
                enable = true;
                ssh = {
                  authorizedKeysFile = "${clientKey}/client.pub";
                  commandLine = ["/bin/success"];
                };
                systemd-credentials = {
                  privateHostKey.file = "${hostkey}/hostkey";
                  privateHostKey.encrypted = false;

                  # This is a bit janky: The module expects to pass
                  # a client ID & secret, but we don't have one
                  # (headscale doesn't support it):
                  clientId.text = "disabled";
                  clientId.encrypted = false;
                  clientSecret.text = "disabled";
                  clientSecret.encrypted = false;
                };
                tailscale = {
                  name = "alice-boot";
                  tags = ["tag:hoopsnake"];
                  environmentFile = envFiles.authKey;
                  tsnetVerbose = true;
                };
              };
            };
          };

          testScript = ''
            with subtest("Test setup"):
                for node in [headscale, bob]:
                        node.start()
                headscale.wait_for_unit("headscale")
                headscale.wait_for_open_port(443)

                # Create headscale user and preauth-key
                headscale.succeed("headscale users create bob")
                authkey = headscale.succeed("headscale preauthkeys -u bob create --reusable")

                # Connect peers
                up_cmd = f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
                bob.execute(up_cmd)
                headscale.succeed("import-pregenerated-keys")

            with subtest("Unlock alice's boot progress"):
                alice.start()
                bob.wait_until_succeeds("tailscale ping alice-boot", timeout=30)
                bob.succeed("ssh-to-alice", timeout=90)
                alice.wait_until_succeeds("test -f /tmp/fnord")
                alice.switch_root()

            with subtest("Finish booting alice"):
                alice.wait_for_unit("multi-user.target", timeout=90)
          '';
        };

        hoopsnake-CVE-2024-45337 = pkgs.testers.runNixOSTest {
          name = "hoopsnake-CVE-2024-45337";
          nodes = {
            inherit headscale mallory;
            alice = {
              lib,
              config,
              ...
            }: let
              fakeShell = pkgs.writeShellApplication {
                name = "success";
                text = "touch /tmp/fnord";
              };
            in {
              imports = [bootloader self.nixosModules.default];
              testing.initrdBackdoor = true;
              boot.initrd.systemd = {
                enable = true;
                initrdBin = [fakeShell];
              };
              boot.initrd.network.hoopsnake = {
                enable = true;
                ssh = {
                  authorizedKeysFile = "${clientKey}/client.pub";
                  commandLine = ["/bin/success"];
                };
                systemd-credentials = {
                  privateHostKey.file = "${hostkey}/hostkey";
                  privateHostKey.encrypted = false;

                  # This is a bit janky: The module expects to pass
                  # a client ID & secret, but we don't have one
                  # (headscale doesn't support it):
                  clientId.text = "disabled";
                  clientId.encrypted = false;
                  clientSecret.text = "disabled";
                  clientSecret.encrypted = false;
                };
                tailscale = {
                  name = "alice-boot";
                  tags = ["tag:hoopsnake"];
                  environmentFile = envFiles.authKey;
                  tsnetVerbose = true;
                };
              };
            };
          };

          testScript = ''
            with subtest("Test setup"):
                for node in [headscale, mallory]:
                        node.start()
                headscale.wait_for_unit("headscale")
                headscale.wait_for_open_port(443)

                # Create headscale user and preauth-key
                headscale.succeed("headscale users create mallory")
                authkey = headscale.succeed("headscale preauthkeys -u mallory create --reusable")

                # Connect peers
                up_cmd = f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
                mallory.execute(up_cmd)
                headscale.succeed("import-pregenerated-keys")

            with subtest("Can't authenticate with a spoofed public key"):
                alice.start()
                mallory.wait_until_succeeds("tailscale ping alice-boot", timeout=30)
                mallory.fail("ssh-to-alice-but-evil", timeout=90)
          '';
        };
      };
  };
}
