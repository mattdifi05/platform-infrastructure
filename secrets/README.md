# Local Secrets

Questa cartella contiene lo store runtime del Secret Manager proprietario Platform e i secret materializzati per Docker Compose.

Regole:

- non committare password, token SMTP, chiavi private o dump sensibili;
- i file reali `*.txt`, lo store cifrato, la master key locale e l'audit log sono ignorati da Git;
- inizializza i secret locali con `sh ./scripts/infra-secret-manager.sh init`;
- valida i secret locali con `sh ./scripts/infra-secret-manager.sh verify`;
- controlla metadata e fingerprint non sensibili con `sh ./scripts/infra-secret-manager.sh status`;
- controlla lo stato KMS con `sh ./scripts/infra-secret-manager.sh kms-status`;
- ruota la KEK locale con `sh ./scripts/infra-secret-manager.sh kms-rotate`;
- avvia lo stack locale con `compose.secrets.yaml`;
- i container leggono i secret da `/run/secrets/*`;
- backend e worker usano variabili `*_FILE`;
- `SESSION_SECRET`, `SESSION_SIGNING_KEYS`, `PROJECTS_GATEWAY_SIGNING_KEYS`, `SECRET_HASH_KEYS`, `BACKUP_SIGNING_KEYS`, `ALERTMANAGER_WEBHOOK_TOKEN`, password DB, SMTP, Redis, MariaDB, MinIO, NATS e Grafana devono essere ruotabili;
- ogni secret deve avere owner, scadenza/rotazione e ambiente (`local`, `staging`, `prod`).

File principali:

- `infra-secret-manager-store.json`: store cifrato AES-256-GCM con envelope KMS proprietario `local-bucket-kms` e KEK derivate HKDF-SHA256;
- `infra-secret-manager-master.key`: master key locale, da proteggere fuori dal repo e includere nel backup sicuro dell'host;
- `infra-secret-manager-audit.log`: audit JSONL delle operazioni;
- `*.txt`: secret materializzati per Docker Compose.
- `projects_gateway_signing_keys.txt`: keyring per il cookie permanente firmato del Control Center su `portal.localhost.com`.
- `mariadb_root_password.txt`: richiesto da `compose.secrets.yaml` e dal profilo `compose.vps.yaml` per evitare password root MariaDB in `.env`.
- `phpmyadmin_control_password.txt`: password dell'utente tecnico `pma`, usata solo quando abiliti manualmente il profilo `admin`.

Su una VPS pubblica proteggi questa cartella con permessi host stretti, backup cifrato e accesso SSH ristretto.
