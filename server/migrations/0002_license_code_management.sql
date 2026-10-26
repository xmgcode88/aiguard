ALTER TABLE license_codes ADD COLUMN IF NOT EXISTS expires_at timestamptz;
ALTER TABLE license_codes ADD COLUMN IF NOT EXISTS redeemed_license_id uuid REFERENCES licenses(id) ON DELETE SET NULL;
ALTER TABLE license_codes ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS idx_license_codes_status_created ON license_codes(status, created_at DESC);
