-- ADR-002 cleanup: backfill 완료 후 평문 PII 컬럼 제거. 모든 행은 암호화 컬럼 + lookup hash를 갖는다.
-- email_hash/email_ciphertext 등은 계정 삭제 redaction(MarkUserDeletedByID)이 NULL로 덮으므로 NOT NULL로 굳히지 않는다.
ALTER TABLE users DROP COLUMN email, DROP COLUMN name;
ALTER TABLE user_identities DROP COLUMN provider_user_id;
