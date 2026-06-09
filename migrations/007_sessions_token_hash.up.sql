-- 세션 bearer 토큰을 평문이 아니라 해시로 저장한다 (ADR-002).
-- 쿠키는 고엔트로피 opaque 토큰을 담고, DB에는 그 SHA-256 해시만 둔다.
-- sessions.id는 내부 PK로만 남고(외부 FK 없음), 조회는 token_hash로 한다.
ALTER TABLE sessions ADD COLUMN token_hash TEXT;

CREATE UNIQUE INDEX sessions_token_hash_key ON sessions (token_hash);
