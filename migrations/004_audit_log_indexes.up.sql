-- #213: audit_log is long-lived and queried by user timeline, event timeline,
-- and retention cutoff. Add narrow indexes for the hot lookup paths without
-- indexing metadata or other high-cardinality payload fields.
CREATE INDEX audit_log_user_created_idx
    ON audit_log (user_id, created_at DESC);

CREATE INDEX audit_log_event_created_idx
    ON audit_log (event_type, created_at DESC);

CREATE INDEX audit_log_created_brin_idx
    ON audit_log USING BRIN (created_at);
