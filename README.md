# A not-featureful SSH server listening on your tailnet, for your initrd

If you live in the 2020, your Linux servers probably have encrypted storage. That means that if you reboot them, you have to provide a password before they can become useful to the world again. The usual way to do this is to include a [dropbear](https://matt.ucc.asn.au/dropbear/dropbear.html) SSH daemon in your init ram file system image, and run it before the `init` process gets started, so you have a chance to SSH in and provide the key material your encrypted drives need to unlock.

I do that too, but I really dislike the idea of having yet another highly-privileged network service that's written in a memory unsafe language listen on the public internet this early in the boot process. So here's a dropbear alternative: hoopsnake.

## Docs

* [Authentication](docs/authentication.md)
* [Threat model](docs/threat-model.md)

## What you get

Hoopsnake can do the following:
* Register a new "device" on your tailnet, like [tsnsrv](https://github.com/boinkor-net/tsnsrv) does
* Start an SSH server (all in go) that listens on `:22` on that tailnet device (so you can reach it, the internet can't!)
* That does public key authentication (no user accounts, you just tell it what program to run) and it spawns whatever program you tell it to run, with the same privileges that hoopsnake runs on; it allocates a PTY if required (so interactive shells/busybox work).

...and that's mostly it.

## What you don't get

* No listening on the public internet. Tailscale (or tailscale with headscale if you like to self-host) is the easiest way to get a VPN that doesn't suck. Please give it a try.
* No SSH extensions like scp/sftp. Too much trouble and I expect you'll only ssh in to type a command and immediately exit again.
* No keyboard-interactive auth. Please use SSH keys. [Secretive](https://github.com/maxgoedjen/secretive) is great if you're on a mac.
* No mitigation for initrd's storing the server's private keys and API tokens in plaintext (see [threat model](docs/threat-model.md#key-management))
* Hopefully no buffer overruns

# How well does it work? Is it stable?

Uh, well. I just uploaded it to github. It seems to do a thing in my personal tests, but should you make the bootability of your machines depend on it? I don't advise that yet.

Is it secure? I'm pretty hopeful that I got the auth portion right, and if not - it'll only listen on a network you alone control (the tailnet). Ideally that doesn't have that many threat actors? In any case, reach me [on Signal](https://signal.me/#eu/VY4kKjsmYkcGO8r5KErpVa2ozLC1zm5j05Jqd18SMzMnqCcWA9tKTr2R4Ngq_7Wh) if you need to report a security issue.

# What's with the name?

A [dropbear](https://en.wikipedia.org/wiki/Drop_bear) is an Australian mythical animal that Australians will insist is totally real, I swear to you, please be afraid.

A [hoop snake](https://en.wikipedia.org/wiki/Hoop_snake) is an Australian mythical animal that Australians will insist is totally real, I swear to you, please be afraid.

To demonstrate how committed I was to the "Australians insisting something is real" bit, check out the git history where this tool started out being named "spidereffer"; let's all be glad that this isn't called that anymore.
