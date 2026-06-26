# Observability

The observability stack includes:

- Prometheus for metrics.
- Grafana for dashboards.
- Loki for logs.
- Promtail for log shipping.
- Alertmanager for routing alerts.
- worker-notifications for email and optional webhook delivery evidence.

## Alerts

Email alerts are configured through SMTP. Optional Discord and Telegram channels are supported only when their secret files are configured.

## External uptime

External uptime can be implemented with Cloudflare Health Checks, Better Stack, UptimeRobot or another provider. Dry-run manifests are not live proof. Production requires provider evidence with fresh status, latency and timestamps.

## Logs

Logs should be redacted before central collection. Evidence lives under `reports/alerts` and `reports/uptime` and must not be committed.
