-- Google hosted domain (the hd claim) from the identity's last upstream login.
-- Per-client access policies match it without an IdP round trip on session
-- reuse, device approval and refresh. NULL when the account has none (consumer
-- Google accounts) or has not signed in since this column was added.
-- An organization domain, not personal data, so it is stored in plaintext.
ALTER TABLE user_identities
ADD COLUMN hosted_domain TEXT;
