# VPS Deployment

The VPS target is Ubuntu LTS or another Linux host with Docker Engine.

## High-level flow

1. Bootstrap the host.
2. Harden SSH/firewall.
3. Prepare `.env` and Docker secret files.
4. Run VPS preflight.
5. Deploy with Compose.
6. Run post-deploy health and evidence checks.

## Commands

```sh
sudo sh ./scripts/vps-hardening-ubuntu.sh --apply --ssh-port 22 --reload-sshd
sh ./scripts/vps-host-readiness.sh --ssh-port 22 --enforce
sh ./scripts/vps-preflight.sh .env
sh ./scripts/vps-postdeploy.sh .env
```

## Rules

- Do not commit real `.env` or `secrets/*.txt`.
- Do not expose database/admin consoles unless protected by a real access layer.
- Keep generated reports outside Git.
- Treat production go/no-go failures as hard stops.
