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
    # keys to build the machines that'll boot into headscale, we
    # have to use "known" API keys
    # that the headscale server knows about; we also need those in
    # the environment file that alice's hoopsnake nixos config
    # module uses; and so: we run a mock headscale server at build
    # time, set up the api keys and then take a DB dump.
    headscaleAccess = let
      config = {
        server_url = "https://headscale";
        listen_addr = "127.0.0.1:8080";
        unix_socket = "@VARLIB@/headscale.sock";
        noise.private_key_path = "@VARLIB@/noise-private.key";
        prefixes.v4 = "100.64.0.0/10";
        derp.server = {
          enabled = true;
          region_id = 999;
          private_key_path = "@VARLIB@/derp-private.key";
          stun_listen_addr = "127.0.0.1:3478";
        };
        database = {
          type = "sqlite";
          sqlite.path = "@VARLIB@/headscale.db";
        };
        dns.magic_dns = false;
      };
      configFile = pkgs.writeText "headscale-setup-config.yaml" (builtins.toJSON config);
    in
      pkgs.runCommand "setup-headscale" {
        nativeBuildInputs = [pkgs.headscale pkgs.sqlite];
      } ''
        set -eux

        mkdir -p $out
        export VARLIB=$(pwd)/var-lib
        mkdir -p $VARLIB

        substitute ${configFile} ./config.yaml --subst-var VARLIB
        headscale serve --config ./config.yaml &
        server_pid="$!"
        trap "kill $server_pid" EXIT
        for try in $(seq 1 10); do
            if [ -e $VARLIB/headscale.sock ]; then
              break
            fi
            sleep 1
        done

        headscale users create --config ./config.yaml bob
        api_key="$(headscale apikeys create --config ./config.yaml)"
        auth_key="$(headscale preauthkeys create --config ./config.yaml -u bob)"
        cat >$out/apikey-envfile <<EOF
        TS_API_KEY=$api_key
        TS_BASE_URL=${config.server_url}
        EOF
        cat >$out/authkey-envfile <<EOF
        TS_AUTHKEY=$auth_key
        TS_BASE_URL=${config.server_url}
        EOF

        trap - EXIT
        kill $server_pid
        wait
        sqlite3 $VARLIB/headscale.db .dump | grep -E -e '^INSERT INTO (api_keys|users|pre_auth_keys)' |tee $out/database-dump.sql
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
            dns.magic_dns = false;
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
            sqlite3 /var/lib/headscale/db.sqlite <${headscaleAccess}/database-dump.sql
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
            alice_ip="$1"
            echo "${hostkey} fingerprint:" >&2
            ssh-keygen -l -f ${hostkey}/hostkey
            echo "${hostkey} contents:" >&2
            cat ${hostkey}/hostkey >&2
            echo "${hostkey}/known_hosts file contents:" >&2
            cat ${hostkey}/known_hosts >&2

            sed "s/^alice-boot/$alice_ip/" ${hostkey}/known_hosts | tee /tmp/resolved-known-hosts
            echo | ssh -v -o UserKnownHostsFile=/tmp/resolved-known-hosts -i /etc/sshKey shell@"$alice_ip"
          '';
        })
      ];
    };
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
                    environmentFile = "${headscaleAccess}/authkey-envfile";
                    tsnetVerbose = true;
                  };
                };
              };
            };
          };

          testScript = ''
            import time
            import json

            def wait_for_hoopsnake_registered(name):
                "Poll until hoopsnake appears in the list of hosts, then return its IP."
                while True:
                    output = json.loads(headscale.succeed("headscale nodes list -o json-line"))
                    print(output)
                    basic_entry = [elt["ip_addresses"][0] for elt in output if elt["given_name"] == name]
                    if len(basic_entry) == 1:
                        return basic_entry[0]
                    time.sleep(1)


            with subtest("Test setup"):
                for node in [headscale, bob]:
                    node.start()
                headscale.wait_for_unit("headscale")
                headscale.wait_for_open_port(${toString headscalePort})
                headscale.wait_for_open_port(443)

                # Import user & hoopsnake auth key
                headscale.succeed("import-pregenerated-keys")
                authkey = headscale.succeed("headscale preauthkeys -u bob create --reusable")

                # Connect peers
                up_cmd = f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
                bob.execute(up_cmd)

            alice.start()
            bob.wait_until_succeeds("tailscale ping alice-boot", timeout=30)
            alice_ip = wait_for_hoopsnake_registered("alice-boot")
            bob.succeed(f"ssh-to-alice {alice_ip}", timeout=90)
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
                  environmentFile = "${headscaleAccess}/authkey-envfile";
                  tsnetVerbose = true;
                };
              };
            };
          };

          testScript = ''
            import time
            import json

            def wait_for_hoopsnake_registered(name):
                "Poll until hoopsnake appears in the list of hosts, then return its IP."
                while True:
                    output = json.loads(headscale.succeed("headscale nodes list -o json-line"))
                    print(output)
                    basic_entry = [elt["ip_addresses"][0] for elt in output if elt["given_name"] == name]
                    if len(basic_entry) == 1:
                        return basic_entry[0]
                    time.sleep(1)

            with subtest("Test setup"):
                for node in [headscale, bob]:
                        node.start()
                headscale.wait_for_unit("headscale")
                headscale.wait_for_open_port(${toString headscalePort})
                headscale.wait_for_open_port(443)

                # Create user and hoopsnake preauth key:
                headscale.succeed("import-pregenerated-keys")

                # Create headscale preauth-key that we use for tailscale
                authkey = headscale.succeed("headscale preauthkeys -u bob create --reusable")

                # Connect peers
                up_cmd = f"tailscale up --login-server 'https://headscale' --auth-key {authkey}"
                bob.execute(up_cmd)

            with subtest("Unlock alice's boot progress"):
                alice.start()
                bob.wait_until_succeeds("tailscale ping alice-boot", timeout=30)
                alice_ip = wait_for_hoopsnake_registered("alice-boot")
                bob.succeed(f"ssh-to-alice {alice_ip}", timeout=90)
                alice.wait_until_succeeds("test -f /tmp/fnord")
                alice.switch_root()

            with subtest("Finish booting alice"):
                alice.wait_for_unit("multi-user.target", timeout=90)
          '';
        };
      };
  };
}
