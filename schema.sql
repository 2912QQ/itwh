CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY,
  salt TEXT NOT NULL,
  hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'viewer' -- admin | viewer
);

CREATE TABLE IF NOT EXISTS devices (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  grp TEXT NOT NULL DEFAULT '默认分组',
  type TEXT DEFAULT '',
  protocol TEXT NOT NULL DEFAULT 'https',
  address TEXT NOT NULL,
  port TEXT DEFAULT '',
  note TEXT DEFAULT '',
  monitor INTEGER NOT NULL DEFAULT 1,  -- 是否启用在线检测
  status INTEGER,                      -- NULL=未检测 1=在线 0=离线
  latency INTEGER,
  checked_at INTEGER
);

CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts INTEGER NOT NULL,
  user TEXT NOT NULL,
  action TEXT NOT NULL,
  detail TEXT DEFAULT '',
  ip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit(ts);

CREATE TABLE IF NOT EXISTS settings (
  k TEXT PRIMARY KEY,
  v TEXT
);
INSERT OR IGNORE INTO settings (k, v) VALUES ('title', '网络设备运维平台');
INSERT OR IGNORE INTO settings (k, v) VALUES ('notice', '');
