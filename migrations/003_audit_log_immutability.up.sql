-- PIPA/SOC2 baseline: audit rows are append-only except for legal/privacy
-- redaction. Core event facts cannot be edited, PII columns can only be
-- nulled, and DELETE is blocked at the table boundary.
CREATE OR REPLACE FUNCTION audit_log_guard_append_only()
RETURNS trigger AS $$
BEGIN
  IF TG_OP = 'DELETE' THEN
    RAISE EXCEPTION 'audit_log rows are append-only';
  END IF;

  IF NEW.id <> OLD.id
     OR NEW.event_type <> OLD.event_type
     OR NEW.created_at <> OLD.created_at
     OR NEW.metadata IS DISTINCT FROM OLD.metadata THEN
    RAISE EXCEPTION 'audit_log immutable fields cannot be updated';
  END IF;

  IF NOT (
    NEW.user_id IS NOT DISTINCT FROM OLD.user_id OR NEW.user_id IS NULL
  ) THEN
    RAISE EXCEPTION 'audit_log user_id can only be redacted to NULL';
  END IF;

  IF NOT (
    NEW.ip_address IS NOT DISTINCT FROM OLD.ip_address OR NEW.ip_address IS NULL
  ) THEN
    RAISE EXCEPTION 'audit_log ip_address can only be redacted to NULL';
  END IF;

  IF NOT (
    NEW.user_agent IS NOT DISTINCT FROM OLD.user_agent OR NEW.user_agent IS NULL
  ) THEN
    RAISE EXCEPTION 'audit_log user_agent can only be redacted to NULL';
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER audit_log_append_only_guard
BEFORE UPDATE OR DELETE ON audit_log
FOR EACH ROW EXECUTE FUNCTION audit_log_guard_append_only();
