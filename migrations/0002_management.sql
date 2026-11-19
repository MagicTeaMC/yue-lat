ALTER TABLE urls ADD COLUMN revoked_at DATETIME;
ALTER TABLE urls ADD COLUMN revoke_reason TEXT;

CREATE TABLE api_keys (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked_at DATETIME
);

CREATE TABLE used_challenges (
    challenge_id TEXT PRIMARY KEY NOT NULL,
    expires_at INTEGER NOT NULL
);
CREATE INDEX used_challenges_expiry ON used_challenges(expires_at);
