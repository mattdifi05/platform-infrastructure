\connect stexor_app

BEGIN;

ALTER TABLE stexor_account.accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.accounts FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS accounts_runtime_access ON stexor_account.accounts;
CREATE POLICY accounts_runtime_access ON stexor_account.accounts
  FOR ALL TO PUBLIC
  USING (
    pg_has_role(current_user, 'stexor_app_account_rw', 'member')
    OR pg_has_role(current_user, 'stexor_app_auth_rw', 'member')
    OR pg_has_role(current_user, 'stexor_app_audit_rw', 'member')
  )
  WITH CHECK (
    pg_has_role(current_user, 'stexor_app_account_rw', 'member')
    OR pg_has_role(current_user, 'stexor_app_auth_rw', 'member')
    OR pg_has_role(current_user, 'stexor_app_audit_rw', 'member')
  );

ALTER TABLE stexor_account.account_roles ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.account_roles FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS account_roles_runtime_access ON stexor_account.account_roles;
CREATE POLICY account_roles_runtime_access ON stexor_account.account_roles
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_account_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_account_rw', 'member'));

ALTER TABLE stexor_account.account_security_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.account_security_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS account_security_settings_runtime_access ON stexor_account.account_security_settings;
CREATE POLICY account_security_settings_runtime_access ON stexor_account.account_security_settings
  FOR ALL TO PUBLIC
  USING (
    pg_has_role(current_user, 'stexor_app_account_rw', 'member')
    OR pg_has_role(current_user, 'stexor_app_auth_rw', 'member')
  )
  WITH CHECK (
    pg_has_role(current_user, 'stexor_app_account_rw', 'member')
    OR pg_has_role(current_user, 'stexor_app_auth_rw', 'member')
  );

ALTER TABLE stexor_account.passkeys ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.passkeys FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS passkeys_runtime_access ON stexor_account.passkeys;
CREATE POLICY passkeys_runtime_access ON stexor_account.passkeys
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.totp_secrets ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.totp_secrets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS totp_secrets_runtime_access ON stexor_account.totp_secrets;
CREATE POLICY totp_secrets_runtime_access ON stexor_account.totp_secrets
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.email_otp_challenges ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.email_otp_challenges FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_otp_challenges_runtime_access ON stexor_account.email_otp_challenges;
CREATE POLICY email_otp_challenges_runtime_access ON stexor_account.email_otp_challenges
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.backup_code_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.backup_code_sets FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS backup_code_sets_runtime_access ON stexor_account.backup_code_sets;
CREATE POLICY backup_code_sets_runtime_access ON stexor_account.backup_code_sets
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.backup_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.backup_codes FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS backup_codes_runtime_access ON stexor_account.backup_codes;
CREATE POLICY backup_codes_runtime_access ON stexor_account.backup_codes
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.sessions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS sessions_runtime_access ON stexor_account.sessions;
CREATE POLICY sessions_runtime_access ON stexor_account.sessions
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.device_approval_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.device_approval_requests FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS device_approval_requests_runtime_access ON stexor_account.device_approval_requests;
CREATE POLICY device_approval_requests_runtime_access ON stexor_account.device_approval_requests
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_auth_rw', 'member'));

ALTER TABLE stexor_account.audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.audit_events FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_events_runtime_access ON stexor_account.audit_events;
CREATE POLICY audit_events_runtime_access ON stexor_account.audit_events
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));

ALTER TABLE stexor_account.service_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.service_catalog FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS service_catalog_runtime_access ON stexor_account.service_catalog;
CREATE POLICY service_catalog_runtime_access ON stexor_account.service_catalog
  FOR SELECT TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_account_rw', 'member'));

ALTER TABLE stexor_account.subscriptions ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.subscriptions FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS subscriptions_runtime_access ON stexor_account.subscriptions;
CREATE POLICY subscriptions_runtime_access ON stexor_account.subscriptions
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_account_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_account_rw', 'member'));

ALTER TABLE stexor_account.email_delivery_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.email_delivery_settings FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_delivery_settings_runtime_access ON stexor_account.email_delivery_settings;
CREATE POLICY email_delivery_settings_runtime_access ON stexor_account.email_delivery_settings
  FOR SELECT TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));

ALTER TABLE stexor_account.email_templates ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.email_templates FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_templates_runtime_access ON stexor_account.email_templates;
CREATE POLICY email_templates_runtime_access ON stexor_account.email_templates
  FOR SELECT TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));

ALTER TABLE stexor_account.email_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.email_outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS email_outbox_runtime_access ON stexor_account.email_outbox;
CREATE POLICY email_outbox_runtime_access ON stexor_account.email_outbox
  FOR ALL TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'))
  WITH CHECK (pg_has_role(current_user, 'stexor_app_audit_rw', 'member'));

ALTER TABLE stexor_account.security_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE stexor_account.security_policies FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS security_policies_runtime_access ON stexor_account.security_policies;
CREATE POLICY security_policies_runtime_access ON stexor_account.security_policies
  FOR SELECT TO PUBLIC
  USING (pg_has_role(current_user, 'stexor_app_account_rw', 'member'));

INSERT INTO stexor_account.security_policies (key, value, description)
VALUES (
  'row_level_security',
  '{"enabled":true,"forced":true,"policyMode":"role-scoped","protectedSchema":"stexor_account"}'::jsonb,
  'All stexor_account runtime tables have forced row-level security with explicit role-scoped policies.'
)
ON CONFLICT (key) DO UPDATE SET
  value = EXCLUDED.value,
  description = EXCLUDED.description,
  updated_at = now();

COMMIT;
