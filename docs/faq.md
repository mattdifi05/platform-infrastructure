# FAQ

## Can I use it without a domain?

Yes for local development and production-like LAN testing. Production go/no-go requires real DNS/TLS evidence.

## Can I use it on a home server?

Yes. Use `home-vps` or `generic-vps` style configuration, but treat it as production-like until live proof exists.

## Can I use Cloudflare Tunnel?

Yes if you document and verify the tunnel as part of provider evidence. It is not required for local development.

## Do I need Docker Windows?

No for production operations. Linux/Docker is the target. Docker Desktop can be used for local development.

## Do I need Node on the VPS?

No for platform operations. The ops runner is container-first.

## Why admin.<domain>?

It separates the control plane from public apps and avoids confusing projects or UI aliases with admin access.

## Where do application projects live?

Outside this repository. Attach them with manifests, runtime config, images and release evidence.

## Can I use Hostinger?

Yes. `hostinger` is an optional provider profile, not default branding.

## Can I use UptimeRobot?

Yes. Any external provider is acceptable if it produces fresh status, latency and timestamp evidence.

## What is needed for production go?

Repo checks, target environment checks and live proof for DNS/TLS, uptime, alerts, off-site restore and release evidence.

## What is GitHub/Sigstore attestation?

A GitHub-signed provenance statement for an artifact or image subject, verified with GitHub Artifact Attestations.

## Is it HA?

The repo is single-node-first. HA planning exists, but production HA requires environment-specific validation.

## Is it ready for open beta?

Only after docs review, secret audit, green safe tests and maintainer onboarding review. The repository license is Apache-2.0.

## Is it a PaaS?

No. It is an infrastructure and control-plane framework.

## Can I use it for multiple clients?

Yes, if each client uses separate manifests, secrets, domains, evidence and provider configuration.
