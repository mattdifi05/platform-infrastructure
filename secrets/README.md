# Local Secrets

Questa cartella contiene lo store runtime del Secret Manager proprietario Stexor e i secret materializzati per Docker Compose.

Regole:

- non committare password, token SMTP, chiavi private o dump sensibili;
- i file reali `*.txt`, lo store cifrato, la master key locale e l'audit log sono ignorati da Git;
- inizializza i secret locali con `sh ./scripts/stexor-secret-manager.sh init`;
- valida i secret locali con `sh ./scripts/stexor-secret-manager.sh verify`;
- controlla metadata e fingerprint non sensibili con `sh ./scripts/stexor-secret-manager.sh status`;
- avvia lo stack locale con `compose.secrets.yaml`;
- i container leggono i secret da `/run/secrets/*`;
- backend e worker usano variabili `*_FILE`;
- `SESSION_SECRET`, `SECRET_HASH_KEYS`, `TOTP_ENCRYPTION_KEYS`, password DB, SMTP, Redis, MinIO, NATS e Grafana devono essere ruotabili;
- ogni secret deve avere owner, scadenza/rotazione e ambiente (`local`, `staging`, `prod`).

File principali:

- `stexor-secret-manager-store.json`: store cifrato AES-256-GCM;
- `stexor-secret-manager-master.key`: master key locale, da proteggere fuori dal repo e includere nel backup sicuro dell'host;
- `stexor-secret-manager-audit.log`: audit JSONL delle operazioni;
- `*.txt`: secret materializzati per Docker Compose.

Su una VPS pubblica proteggi questa cartella con permessi host stretti, backup cifrato e accesso SSH ristretto.
