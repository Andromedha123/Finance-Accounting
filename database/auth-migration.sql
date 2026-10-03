-- Jalankan SEKALI pada database sppg_finance Anda yang sudah memiliki users/audit_logs.
-- Aman dijalankan berulang kali.

ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS old_data JSONB NULL;
ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS new_data JSONB NULL;

CREATE INDEX IF NOT EXISTS audit_logs_created_at_idx ON audit_logs (created_at DESC);
CREATE INDEX IF NOT EXISTS audit_logs_user_id_idx ON audit_logs (user_id);
CREATE INDEX IF NOT EXISTS audit_logs_module_idx ON audit_logs (module);
