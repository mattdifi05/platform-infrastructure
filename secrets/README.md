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
- backend e worker usano variabili `*_FILE` e URL PostgreSQL distinti;
- `SESSION_SECRET`, `SESSION_SIGNING_KEYS`, `PROJECTS_GATEWAY_SIGNING_KEYS`, `SECRET_HASH_KEYS`, `BACKUP_SIGNING_KEYS`, `ALERTMANAGER_WEBHOOK_TOKEN`, password DB, SMTP, Redis, MariaDB, MinIO, NATS e Grafana devono essere ruotabili;
- ogni secret deve avere owner, scadenza/rotazione e ambiente (`local`, `staging`, `prod`).

File principali:

- `infra-secret-manager-store.json`: store cifrato AES-256-GCM con envelope KMS proprietario `local-bucket-kms` e KEK derivate HKDF-SHA256;
- `infra-secret-manager-master.key`: master key locale, da proteggere fuori dal repo e includere nel backup sicuro dell'host;
- `infra-secret-manager-audit.log`: audit JSONL delle operazioni;
- `*.txt`: secret materializzati per Docker Compose.
- `projects_gateway_signing_keys.txt`: keyring del project gateway; resta montato nel Control Center solo come sorgente legacy read-only durante la migrazione Vault v1.
- `control_center_vault_keys.txt`: keyring dedicato e versionato per la cifratura del Vault Control Center. Non condividerlo con sessioni o gateway; conserva le vecchie chiavi finche i relativi ciphertext e backup non sono scaduti o restore-testati.
- `mariadb_root_password.txt`: richiesto da `compose.secrets.yaml` e dal profilo `compose.vps.yaml` per evitare password root MariaDB in `.env`.
- `phpmyadmin_control_password.txt`: password dell'utente tecnico `pma`, usata solo quando abiliti manualmente il profilo `admin`.
- `backend_db_password.txt` / `backend_database_url.txt`: identita PostgreSQL del backend ospitato.
- `worker_jobs_db_password.txt` / `worker_jobs_database_url.txt`: identita PostgreSQL del worker jobs, limitata a outbox e metriche restore.
- `worker_notifications_db_password.txt` / `worker_notifications_database_url.txt`: identita connect-only del worker notifiche; nessun grant su tabelle.

`database_url.txt` e `app_db_password.txt` sono compatibilita temporanea per il
rollout dual-credential. Non devono essere montati su backend o worker dopo
T14. La revoca di `app_user` e separata dalla migrazione grant e richiede
evidence di backup/restore e cutover. Le chiavi MinIO per workload sono secret
Vault on-demand e devono essere associate a un solo bucket/prefix; non sono
secret globali obbligatori quando nessun workload usa object storage.

Su una VPS pubblica proteggi questa cartella con permessi host stretti, backup cifrato e accesso SSH ristretto.
