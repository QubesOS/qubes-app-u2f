# Qubes OS U2F proxy

## Architecture diagram

![Architecture diagram](Documentation/architecture.svg)

## Requirements

*This section is a draft*

```
dnf install python3-hidapi
```

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
provided by the U2F protocol itself.
