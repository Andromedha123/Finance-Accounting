-- SPPG Finance - Authentication & Audit Trail
-- Jalankan di database sppg_finance setelah schema.sql utama.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL,
  full_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'staff'
    CHECK (role IN ('admin','staff','auditor')),
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  last_login_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_username_lower_uq
  ON users (LOWER(username));

CREATE TABLE IF NOT EXISTS audit_logs (
  id BIGSERIAL PRIMARY KEY,
  user_id TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
  username TEXT NOT NULL DEFAULT '',
  action TEXT NOT NULL,
  module TEXT NOT NULL DEFAULT '',
  record_id TEXT NULL,
  description TEXT NOT NULL DEFAULT '',
  ip_address TEXT NULL,
  user_agent TEXT NULL,
  old_data JSONB NULL,
  new_data JSONB NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx
  ON audit_logs (created_at DESC);

CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx
  ON audit_logs (user_id);

CREATE INDEX IF NOT EXISTS audit_logs_module_idx
  ON audit_logs (module);

-- Admin awal.
-- PASSWORD DI SINI HANYA CONTOH DAN WAJIB DIGANTI.
-- Hash dibuat oleh script Node di bawah, bukan ditulis manual.
