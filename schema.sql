-- Issued passes. One row per person holding a pass.
CREATE TABLE IF NOT EXISTS passes (
  serial_number        TEXT PRIMARY KEY,
  authentication_token TEXT NOT NULL,
  -- JSON object merged into the template's pass.json at signing time.
  -- e.g. {"primaryFields":[{"key":"bling","value":"\u2728\u2728\u2728"}]}
  overrides            TEXT NOT NULL DEFAULT '{}',
  updated_at           INTEGER NOT NULL,
  created_at           INTEGER NOT NULL,
  voided               INTEGER NOT NULL DEFAULT 0
);

-- Devices that have registered for updates to a given pass.
CREATE TABLE IF NOT EXISTS registrations (
  device_library_identifier TEXT NOT NULL,
  serial_number             TEXT NOT NULL,
  push_token                TEXT NOT NULL,
  created_at                INTEGER NOT NULL,
  PRIMARY KEY (device_library_identifier, serial_number)
);

CREATE INDEX IF NOT EXISTS idx_registrations_serial
  ON registrations (serial_number);

CREATE INDEX IF NOT EXISTS idx_passes_updated_at
  ON passes (updated_at);

-- Device-reported errors from POST /v1/log. Handy when Wallet silently
-- refuses a pass: the reason shows up here.
CREATE TABLE IF NOT EXISTS device_logs (
  id         INTEGER PRIMARY KEY AUTOINCREMENT,
  message    TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
