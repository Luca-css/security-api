-- 001: initial schema
CREATE TABLE users (
  id            TEXT PRIMARY KEY,
  username      TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  role          TEXT NOT NULL CHECK (role IN ('admin', 'analyst')),
  created_at    TEXT NOT NULL
);

CREATE TABLE threats (
  id            TEXT PRIMARY KEY,
  source_ip     TEXT NOT NULL,
  type          TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  description   TEXT NOT NULL,
  country       TEXT,
  attack_vector TEXT,
  detected_at   TEXT NOT NULL,
  resolved      INTEGER NOT NULL DEFAULT 0,
  resolved_at   TEXT,
  resolved_by   TEXT,
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
CREATE INDEX idx_threats_detected_at ON threats (detected_at);
CREATE INDEX idx_threats_source_ip ON threats (source_ip);

CREATE TABLE alerts (
  id            TEXT PRIMARY KEY,
  title         TEXT NOT NULL,
  severity      TEXT NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  source        TEXT NOT NULL,
  description   TEXT,
  affected_host TEXT,
  resolved      INTEGER NOT NULL DEFAULT 0,
  resolved_at   TEXT,
  resolved_by   TEXT,
  created_by    TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
CREATE INDEX idx_alerts_created_at ON alerts (created_at);

CREATE TABLE blocklist (
  id         TEXT PRIMARY KEY,
  cidr       TEXT NOT NULL UNIQUE,
  reason     TEXT NOT NULL,
  expires_at TEXT,
  hits       INTEGER NOT NULL DEFAULT 0,
  created_by TEXT NOT NULL,
  created_at TEXT NOT NULL
);
