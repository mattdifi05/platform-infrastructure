\connect app_db

BEGIN;

CREATE OR REPLACE FUNCTION app_account.prevent_audit_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF TG_OP = 'UPDATE'
     AND OLD.account_id IS NOT NULL
     AND NEW.account_id IS NULL
     AND (to_jsonb(OLD) - 'account_id') = (to_jsonb(NEW) - 'account_id') THEN
    RETURN NEW;
  END IF;

  RAISE EXCEPTION 'audit_events_are_append_only';
END;
$$;

COMMENT ON FUNCTION app_account.prevent_audit_event_mutation() IS 'Audit events are append-only; only FK-driven account_id nullification is allowed for account deletion/anonymization cleanup.';

COMMIT;
