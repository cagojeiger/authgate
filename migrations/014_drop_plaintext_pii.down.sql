-- 되돌리기: 컬럼 구조만 재생성(평문 데이터는 복구 불가). 구 UNIQUE도 복원.
ALTER TABLE users ADD COLUMN email TEXT, ADD COLUMN name TEXT;
CREATE UNIQUE INDEX users_email_key ON users (email);
ALTER TABLE user_identities ADD COLUMN provider_user_id TEXT;
ALTER TABLE user_identities ADD CONSTRAINT user_identities_provider_provider_user_id_key UNIQUE (provider, provider_user_id);
