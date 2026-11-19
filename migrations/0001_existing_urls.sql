-- Adopt databases created by the original yue-lat application.
CREATE TABLE IF NOT EXISTS urls (
    short_code TEXT PRIMARY KEY CHECK(length(short_code) <= 20),
    original_url TEXT NOT NULL CHECK(length(original_url) <= 2048),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
