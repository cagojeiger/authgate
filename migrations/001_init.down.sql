-- Reverses 001_init.up.sql
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS device_codes;
DROP TABLE IF EXISTS auth_requests;
DROP TABLE IF EXISTS refresh_tokens;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS user_identities;
DROP TABLE IF EXISTS users;
DROP EXTENSION IF EXISTS "uuid-ossp";
