ALTER TABLE urls ADD COLUMN edit_token_hash TEXT;
CREATE UNIQUE INDEX urls_edit_token_hash ON urls(edit_token_hash) WHERE edit_token_hash IS NOT NULL;

ALTER TABLE urls ADD COLUMN created_by_api_key_id INTEGER REFERENCES api_keys(id);
ALTER TABLE urls ADD COLUMN expires_at INTEGER;
ALTER TABLE urls ADD COLUMN password_hash TEXT;
ALTER TABLE urls ADD COLUMN max_visits INTEGER CHECK(max_visits > 0);
ALTER TABLE urls ADD COLUMN visit_count INTEGER NOT NULL DEFAULT 0 CHECK(visit_count >= 0);
ALTER TABLE urls ADD COLUMN updated_at DATETIME;
