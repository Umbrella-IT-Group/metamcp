# Security Policy

This is a maintained, security-hardened downstream fork of
[metatool-ai/metamcp](https://github.com/metatool-ai/metamcp). Security fixes land on
the `umbrella` branch (the default, deployable line); `main` mirrors upstream.

## Reporting a vulnerability

Please report security issues privately — do not open a public issue or PR:

- Preferred: open a [private security advisory](https://github.com/Umbrella-IT-Group/metamcp/security/advisories/new)
  on this repository.
- Or email **support@umbrellaitgroup.com** with "metamcp security" in the subject.

We aim to acknowledge within 3 business days and to agree a coordinated disclosure timeline with you.

## Threat model

We maintain a threat model for our deployment of this fork privately; it is not published in
this repository. Vulnerability reports should go to the contact published in the deployment's
`/.well-known/security.txt` (currently `mailto:support@umbrellaitgroup.com`), or through the
private advisory process above.

## Scope

In scope: the `umbrella` branch of this repository — the gateway, its management API, OAuth
surface, and the container/compose configuration in this repo.

Out of scope: upstream-only code paths not present on `umbrella` (report those to
[metatool-ai/metamcp](https://github.com/metatool-ai/metamcp)); third-party dependencies
(report upstream, though a heads-up is welcome); and any deployment we do not operate.

## Coordinated disclosure

Where a weakness we fix also affects upstream metamcp, we report it privately to the upstream
maintainers and contribute the fix back before publishing specifics. Please extend us the same
courtesy: a reasonable window to fix and coordinate before public disclosure.

## Supported versions

The `umbrella` branch is the supported, deployable line and receives security fixes.
Prebuilt images: `ghcr.io/umbrella-it-group/metamcp`.
