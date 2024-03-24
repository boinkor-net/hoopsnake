# Overview

When running a headless machine that stores data, there are two primary issues that we must work towards preventing:

* Loss of data (including access to it), and
* Unauthorized access to data.

These two must remain in balance: If nobody has access to the data, you have prevented unauthorized access, but you yourself also have no access. If everyone has access to the data, someone malicious can use that access to read your secrets or corrupt your work, or remove your own access.

## What hoopsnake focuses on

Hoopsnake is software meant to run on computers that use full-disk encryption (FDE), running headlessly (living in a data center / basement somewhere, no monitor attached). FDE requires some sort of key material up-front, and short of shipping that key material on the machine itself (unencrypted or sealed in a TPM), there needs to be a way to provide it from outside the machine.

Hoopsnake runs an SSH daemon that allows automatic or manual entry of that FDE key from the outside.

## Issue 1: Loss of (access to) data

The issues that affect hoopnake mostly have the shape "your boot process doesn't work the way you expected, now you have to fetch the KVM/crash cart & fix it in person". We really want the boot process to always work. Ideally, hoopsnake will always be able to provide an SSH service to users on your tailnet.

## Issue 2: Unauthorized access to data

Several bad things can happen if a malicious actor gets elevated privileges on your stuff: They can use that access to install malware, copy your data, or simply lock you out from your own access. None of that is an acceptable outcome, so a safe approach must to some extent trade off Issue 1 for the consequences of Issue 2.

## Constraints and how they relate to the two issues

* The stage1 boot environment has almost no persistent storage - everything you "write" goes into a ramdisk at best and will be lost after stage1, not to mention at the next boot. (Issue 1)
* A trustworthy remote party who wants to unblock the boot process does not know if the machine was physically compromised prior to that boot process (Issue 2 AND Issue 1)
* Remote parties often rely on automated tooling to unblock the boot process; doing that should require as little manual interaction as possible (Issue 1)

# How hoopsnake tips the scales between the two issues

Mostly, we treat loss of access to data as less problematic than unauthorized access: Often there are alternative ways to get the machine to finish booting, so that is less unacceptable than another party being able to gain access to your system.

## No persistent storage in stage1 boot

Tailscale defaults to really wanting persistent storage: Each node that it registers (even an ephemeral node) requires a state directory, which contains what I'll call a session key for the node, and some other stuff. Unfortunately at stage1, we have no persistent file systems where crypto stuff could be stored: That's the whole point of stage1, after all.

Hoopsnake tries to ensure that no state between boots needs to persist: To that end, it:

* registers as an ephemeral node (about an hour after the hoopsnake process gets killed, the node state gets cleaned up on the tailscale side),
* puts the state directory on volatile storage
* supports using expiration-free oauth2 client key material

## Secrets management

`hoopsnake` does nothing to mitigate the issue that initrd "secrets" aren't: By default, they are unencrypted bits on disk that can be read from a VFAT partition with approximately zero effort.

That means that if somebody gets physical-enough access to your machine (or enough access to read an initrd file), they can extract (and AFAICT, the following applies exactly to `hoopsnake` as well as to `dropbear`):

* the SSH private key that the server uses to authenticate to clients,
* the tailscale API keys that hoopsnake uses to control the tailscale API (registering devices if it's an authkey or "god powers" if it's an unrestricted API key; more limited powers than "god" if it's an oauth keypair).

A skilled adversary can take that information to trick you into providing your full-disk encryption password, if your device gets compromised, then rebooted, and you don't know that this has happened.

### Possible mitigations

The main ways to work around this is to use some sort of hardware cryptography to seal the secrets away until only a non-compromised device & boot process can request them. That's a TPM (version 2).

However, if you modify your system sufficient amounts, these values might not unseal correctly anymore and you're locked out... so please be mindful of that.

You can probably use something like [`systemd-creds`](https://www.freedesktop.org/software/systemd/man/latest/systemd-creds.html) to seal the `hoopsnake` API and SSH keys. I would love to try that out one day!

## A stable remote-access API

People will be using automatic tools to provide FDE keys (e.g. running scripts to retrieve the secret from secure storage, then run ssh with a restricted known_hosts set and automatically enter the sequence that unlocks the disks). To that end, we must make sure the interface we present doesn't randomly inject variations that need human interaction.

One example here is that when registering a node named "foo", tailscale will not deallocate another node named "foo" if it exists and has been offline for any amount of time, even if that node was ephemeral. It will allocate a node named "foo-1", and anyone ssh'ing into "foo" needs to use the other hostname and construct a matching known_hosts file.

That's pretty unacceptable, so if hoopsnake has tailscale API keys (scope-limited oauth2 or full API), it will find any colliding nodes that haven't been offline for a set time period (defaulting to 30s) and delete them.

# Conclusion: This is incomplete

Of course, this document is not complete (or will ever be complete, I think). Please help flesh it out - pull requests are highly desired.
