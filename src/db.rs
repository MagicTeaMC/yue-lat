use anyhow::{Context, Result, ensure};
use rand::TryRngCore;
use sha2::{Digest, Sha256};
use sqlx::{Row, SqlitePool, sqlite::SqliteConnectOptions};
use std::time::Duration;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

pub async fn open(path: &str, create: bool) -> Result<SqlitePool> {
    let options = if path == ":memory:" {
        "sqlite::memory:".parse::<SqliteConnectOptions>()?
    } else {
        SqliteConnectOptions::new().filename(path)
    };
    SqlitePool::connect_with(
        options
            .create_if_missing(create)
            .busy_timeout(Duration::from_secs(5))
            .pragma("journal_mode", "WAL")
            .pragma("synchronous", "NORMAL")
            .pragma("foreign_keys", "true"),
    )
    .await
    .with_context(|| format!("Cannot open database {path}"))
}

pub async fn setup(path: &str) -> Result<SqlitePool> {
    let db = open(path, true).await?;
    MIGRATOR
        .run(&db)
        .await
        .context("Database migration failed")?;
    Ok(db)
}

pub fn hash_key(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes()))
}

pub async fn create_key(db: &SqlitePool, name: &str) -> Result<(i64, String)> {
    ensure!(
        !name.trim().is_empty() && name.len() <= 100,
        "Name must be 1–100 bytes"
    );
    let mut bytes = [0_u8; 32];
    rand::rngs::OsRng
        .try_fill_bytes(&mut bytes)
        .context("Cannot generate API key")?;
    use base64::Engine;
    let key = format!(
        "qkg_{}",
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(bytes)
    );
    let result = sqlx::query("INSERT INTO api_keys (name, key_hash) VALUES (?, ?)")
        .bind(name.trim())
        .bind(hash_key(&key))
        .execute(db)
        .await?;
    Ok((result.last_insert_rowid(), key))
}

pub async fn key_is_active(db: &SqlitePool, key: &str) -> Result<bool> {
    if key.len() > 256 {
        return Ok(false);
    }
    Ok(
        sqlx::query("SELECT 1 FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL")
            .bind(hash_key(key))
            .fetch_optional(db)
            .await?
            .is_some(),
    )
}

pub async fn revoke_key(db: &SqlitePool, id: i64) -> Result<()> {
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = COALESCE(revoked_at, CURRENT_TIMESTAMP) WHERE id = ?",
    )
    .bind(id)
    .execute(db)
    .await?;
    ensure!(result.rows_affected() == 1, "API key ID not found");
    Ok(())
}

pub async fn revoke_link(db: &SqlitePool, code: &str, reason: &str) -> Result<()> {
    ensure!(
        !reason.trim().is_empty() && reason.len() <= 1000,
        "Reason must be 1–1000 bytes"
    );
    let result = sqlx::query("UPDATE urls SET revoked_at = CURRENT_TIMESTAMP, revoke_reason = ? WHERE short_code = ? AND revoked_at IS NULL")
        .bind(reason.trim()).bind(code).execute(db).await?;
    if result.rows_affected() == 0 {
        let exists = sqlx::query("SELECT 1 FROM urls WHERE short_code = ?")
            .bind(code)
            .fetch_optional(db)
            .await?;
        ensure!(exists.is_some(), "Short code not found");
        // Preserve the first revocation timestamp and reason on repeated commands.
    }
    Ok(())
}

pub async fn check(path: &str) -> Result<()> {
    // A check must not create a database or apply pending migrations.
    let options = SqliteConnectOptions::new().filename(path).read_only(true);
    let db = SqlitePool::connect_with(options).await?;
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(&db)
        .await?;
    ensure!(
        count == MIGRATOR.iter().count() as i64,
        "Database migration versions differ; run the matching QuickGo version and quickgo migrate"
    );
    for migration in MIGRATOR.iter() {
        let row = sqlx::query("SELECT success, checksum FROM _sqlx_migrations WHERE version = ?")
            .bind(migration.version)
            .fetch_optional(&db)
            .await?;
        let row = row.context("Database has pending migrations; run quickgo migrate")?;
        ensure!(
            row.get::<bool, _>("success"),
            "Database has an unsuccessful migration"
        );
        ensure!(
            row.get::<Vec<u8>, _>("checksum") == migration.checksum.as_ref(),
            "Migration checksum mismatch"
        );
    }
    let result: String = sqlx::query_scalar("PRAGMA quick_check")
        .fetch_one(&db)
        .await?;
    ensure!(result == "ok", "Database check failed: {result}");
    db.close().await;
    Ok(())
}
