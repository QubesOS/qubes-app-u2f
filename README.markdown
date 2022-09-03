# Qubes OS U2F proxy

This tool is intended to securely forward U2F challenge-response authentication
between Web browser and U2F HID token without exposing the browser and USB stack
to one another.

This implements [FIDO U2F version 1.2][U2FRawMsgs] with [HID
encapsulation][U2FHID]. See also non-normative [U2F Overview][U2FOverview] for
introduction and U2F threat model.

![Screenshot](Documentation/screenshot.png)

## HOWTO

### Requirements

- Qubes R4.1 or later
- For Debian template: Debian 10 (stretch) or later
- For Fedora template: Fedora 35 or later
- Python 3.5 or later
- https://github.com/Yubico/python-u2flib-host
- For building manpages: `python3-sphinx`

### Installation

The guide assumes there is `sys-usb` qube which holds the USB Host PCI device
and the qube which holds the browser (or other U2F client) is named `work`.

1. In `debian-11`:
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
`/etc/qubes-rpc/policy/policy.RegisterArgument+u2f.Authenticate` with the
following content:

```
sys-usb $anyvm allow,target=dom0
```

Then remove `/etc/qubes-rpc/policy/u2f.Authenticate` and register your token.
After doing this, any qube will have access only to tokens enrolled using that
particular qube. Also, any previously registered token will not work.

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
certainly are some, since the user is deploying U2F authentication to protect
them in the first place. That access should not be possible.

It is explicitly not a&nbsp;goal to ensure any security properties already
provided by the U2F protocol itself. It is also not a&nbsp;goal to prevent
cooperative channels between the browser and the token.

## Architecture diagram

![Architecture diagram](Documentation/architecture.svg)

## Incompatibilities

WINK does not work, even if the underlying harware token does support it.

[U2FOverview]: https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-overview-v1.2-ps-20170411.html
[U2FRawMsgs]: https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-raw-message-formats-v1.2-ps-20170411.html
[U2FHID]: https://fidoalliance.org/specs/fido-u2f-v1.2-ps-20170411/fido-u2f-hid-protocol-v1.2-ps-20170411.html

<!-- vim: set tw=80 : -->
