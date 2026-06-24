\connect app_db

CREATE TABLE IF NOT EXISTS app_account.account_roles (
  account_id uuid NOT NULL REFERENCES app_account.accounts(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('owner', 'admin', 'developer', 'billing', 'viewer')),
  granted_by uuid REFERENCES app_account.accounts(id) ON DELETE SET NULL,
  granted_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  PRIMARY KEY (account_id, role)
);

CREATE INDEX IF NOT EXISTS idx_account_roles_active
  ON app_account.account_roles(account_id, role)
  WHERE revoked_at IS NULL;

CREATE TABLE IF NOT EXISTS app_account.security_policies (
  key text PRIMARY KEY,
  value jsonb NOT NULL,
  description text NOT NULL DEFAULT '',
  updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO app_account.account_roles (account_id, role)
SELECT account.id, 'owner'
FROM app_account.accounts account
WHERE account.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM app_account.account_roles role
    WHERE role.account_id = account.id
      AND role.revoked_at IS NULL
  )
ORDER BY account.created_at ASC
LIMIT 1
ON CONFLICT (account_id, role) DO NOTHING;

INSERT INTO app_account.account_roles (account_id, role)
SELECT account.id, 'viewer'
FROM app_account.accounts account
WHERE account.deleted_at IS NULL
  AND NOT EXISTS (
    SELECT 1
    FROM app_account.account_roles role
    WHERE role.account_id = account.id
      AND role.revoked_at IS NULL
  )
ON CONFLICT (account_id, role) DO NOTHING;

INSERT INTO app_account.security_policies (key, value, description)
VALUES
  ('account_session', '{"cookie":"HttpOnly Secure SameSite=Lax","rememberMeSeconds":315360000,"requireServerSession":true}'::jsonb, 'Account session policy'),
  ('backup', '{"postgres":"daily","restoreTest":"monthly","encryptOffsite":true}'::jsonb, 'Backup and restore policy')
ON CONFLICT (key) DO UPDATE SET
  value = EXCLUDED.value,
  description = EXCLUDED.description,
  updated_at = now();

COMMENT ON TABLE app_account.account_roles IS 'Server-side RBAC grants for Platform accounts.';
COMMENT ON TABLE app_account.security_policies IS 'Versioned runtime security policy defaults.';

GRANT SELECT, INSERT, UPDATE, DELETE ON app_account.account_roles TO app_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON app_account.security_policies TO app_user;
