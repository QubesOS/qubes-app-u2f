# Qubes OS CTAP proxy

This tool is intended to securely forward CTAP challenge-response authentication
between Web browser and CTAP HID token without exposing the browser and 
USB stack to one another.

This implements [FIDO 2][FIDO2] with [HID encapsulation][CTAPHID].

![Screenshot](Documentation/screenshot.png)

## HOWTO

### Requirements

- Qubes R4.1 or later
- TODO: For Debian template: Debian 10 (stretch) or later
- For Fedora template: Fedora 35 or later
- Python 3.7 or later
- https://github.com/Yubico/python-u2flib-host
- For building manpages: `python3-sphinx`

### Installation

The guide assumes there is `sys-usb` qube which holds the USB Host PCI device
and the qube which holds the browser (or other CTAP client) is named `work`.

1. In `debian-11` (TODO):
```
sudo apt install qubes-u2f
```
1. In `fedora-36`:
```
sudo dnf install qubes-u2f
```
1. In `dom0`:
```
qubes-dom0-update qubes-u2f-dom0
qvm-service --enable work qubes-u2f-proxy
```

### Advanced: per-qube access enforced by policy

In `dom0`, create a file
`/etc/qubes-rpc/policy/policy.RegisterArgument+ctap.GetAssertion` with the
following content:

```
sys-usb $anyvm allow,target=dom0
```

Then truncate `/etc/qubes-rpc/policy/ctap.GetAssertion` to 0 bytes and register
your token. After doing this, any qube will have access only to tokens enrolled
using that particular qube. Also, any previously registered token will not work.

## Threat model

Threat model is two-ways, both frontend and backend are untrusted from each
others point of view. It is assumed that either side could be taken control of
by an attacker: for example the backend domain could have vulnerabilities in USB
stack and frontend domain can be taken over via exploit against web browser. It
is further assumed that either side is capable of sending arbitrary messages
within the constraints of qrexec policy.

The aim of the frontend site would be typically to get unlimited access to
token, and possibly key materiel if the token is software-only. The aim of the
backend would be to get access to any secrets held in frontend domain, and there
certainly are some, since the user is deploying CTAP authentication to protect
them in the first place. That access should not be possible.

It is explicitly not a&nbsp;goal to ensure any security properties already
provided by the CTAP protocol itself. It is also not a&nbsp;goal to prevent
cooperative channels between the browser and the token.

## Architecture diagram

![Architecture diagram](Documentation/architecture.svg)

## Incompatibilities

WINK does not work, even if the underlying harware token does support it.

[FIDO2]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html
[CTAPHID]: https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-errata-20220621.html#transport-specific-bindings

<!-- vim: set tw=80 : -->
