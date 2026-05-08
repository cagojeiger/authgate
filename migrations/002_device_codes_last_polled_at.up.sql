-- #188 / RFC 8628 §3.5: track the timestamp of the last token-endpoint poll
-- per device_code so the AS can enforce the advertised `interval` and
-- respond with `slow_down` when a client polls faster than allowed.
-- NULL means "never polled yet" — the first poll always proceeds and
-- seeds the column.
ALTER TABLE device_codes
    ADD COLUMN last_polled_at TIMESTAMPTZ;
