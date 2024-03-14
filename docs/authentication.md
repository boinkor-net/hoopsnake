# Authentication in hoopsnake

There are two main ways authentication happens: The authentication
that hoopsnake does to the tailnet, and the authentication that
happens between the hoopsnake SSH server and an SSH client.

## Tailnet authentication

In order for hoopsnake to get a "device" registered the tailnet, it
needs a pre-authenticated key (an "authkey" in tailscale docs). These
can come in several ways, and of course there is a recommendation to
you for the best method:

* Specify an authkey on the environment directly
* Specify an API key, and hoopsnake mints an ephemeral authkey from that
* Specify an [oauth client ID and
  secret](https://tailscale.com/kb/1215/oauth-clients), and hoopsnake
  mints an ephemeral authkey from that.

Unfortunately, if you're using tailscale, the last method (the oauth
client keypair) is the best and most reasonable way to keep your
devices booting, and stay securely out of other devices' ways.

### Auth and "all-powerful" API access tokens

You can make one of these in the
[Keys](https://login.tailscale.com/admin/settings/keys) section in
your tailnet console (or with the headscale CLI).

In tailnet at least, these have a 90-day lifetime limit. I don't
recommend them specifically due to this limit: If you reboot your
machine on day 91, you are locked out and life sucks until you have
gotten the machine back online & minted another key, then gotten that
put on the machine. And in 91 days, that same issue repeats. It is not
great.

To use auth or api keys:

1. Generate one on the [Keys](https://login.tailscale.com/admin/settings/keys) page
2. If you generated an auth key, set `TS_AUTHKEY` to that value
3. If you generated an API key, set `TS_API_KEY` to that value
4. Remember - you only need either an auth or an api key.
4. Run `headscale ...`
5. Remember to rotate the key every 90 days!

### Oauth keypairs on tailscale (recommended!)

So instead, tailscale lets you make scoped oauth access keys, which
not only have *way* less power than API keys (but plenty of power in
the area we need!), and have an unrestricted lifetime.

Unless you revoke the oauth token, your machine will remain able to
boot.

To use oauth keypairs,

1. Set up an ACL tag on the
   [ACL](https://login.tailscale.com/admin/acls/file) page, under the
   `tagOwners` key.
2. Ensure whatever devices you use to access your `hoopsnake` SSH
   service have access to devices tagged that, port `22`. That's under
   the `acls` key.
2. Generate one on [the oauth clients
   page](https://login.tailscale.com/admin/settings/oauth) and bind it
   to that tag.
2. Set the env variable `TS_API_CLIENT_ID` to the client ID
3. Set the env variable `TS_API_CLIENT_SECRET` to the client secret
4. Run `headscale ...` and it should be a proper tailscale oauth client.

### other considerations: Cleaning out old device entries

`hoopsnake` will mint auth tokens that generate "ephemeral"
devices. That means that once you're finished booting, the device goes
away and gets cleaned up by tailscale. The next time you boot
(hopefully not within a half hour to a few hours), the
"your-device-name" name will be free, and you can still reach it under
that name.

...that is, if you do only reboot only when the tailscale ephemeral
cleanout job has had a chance to run. `headscale` has an option
`-deleteExisting` (with `-maxNodeAge`) that will search for nodes that
have the same name as the requested name, and if they've been offline
for at least `maxNodeAge`, will delete them before registering itself.

If you use the oauth client authentication method, you can use
`-deleteExisting`, and I highly recommend it.

# SSH authentication

`hoopsnake` supports only SSH public key authentication. Use the flag
`-authorizedKeys` to specify an `authorized_keys` file in the typical
SSH format. You can even generate one from github if you like, with
the following commandline: `curl
https://api.github.com/users/$(whoami)/keys | jq -r '.[].key'` (that
is, if your login name is your github username; substitute that
`$(whoami)` for your github username if not).

The SSH server also needs a private key to finish the handshake (and
authentication _to_ the client). You can generate one with the
commandline `ssh-keygen -t ssh-keygen -t ed25519 -f hoopsnake` and
tell hoopsnake to use that file with the `-hostKey` flag.

# Threat model pieces

## Key management

`hoopsnake` does nothing to mitigate the issue that initrd "secrets"
aren't: By default, they are unencrypted bits on disk that can be read
from a VFAT partition with approximately zero effort.

That means that if somebody gets physical-enough access to your
machine (or enough access to read an initrd file), they can extract
(and AFAICT, the following applies exactly to `hoopsnake` as well as
to `dropbear`):

* the SSH private key that the server uses to authenticate to clients,
* the tailscale API keys that hoopsnake uses to control the tailscale
  API (registering devices if it's an authkey or "god powers" if it's
  an unrestricted API key; more limited powers than "god" if it's an
  oauth keypair).

A skilled adversary can take that information to trick you into
providing your full-disk encryption password, if your device gets
compromised, then rebooted, and you don't know that this has happened.

### Possible mitigations

The main ways to work around this is to use some sort of hardware
cryptography to seal the secrets away until only a non-compromised
device & boot process can request them. That's a TPM (version 2).

However, if you modify your system sufficient amounts, these values
might not unseal correctly anymore and you're locked out... so please
be mindful of that.

You can probably use something like
[`systemd-creds`](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html)
to seal the `hoopsnake` API and SSH keys. I would love to try that out
one day!
