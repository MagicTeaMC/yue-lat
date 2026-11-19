use std::{
    collections::HashMap,
    hash::Hash,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use argon2::{
    Argon2,
    password_hash::{Error, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use axum::http::StatusCode;
use tokio::sync::Semaphore;

use crate::{ErrorResponse, api_error, db};

pub struct RateLimit<K> {
    window: Mutex<Window<K>>,
    total_limit: u32,
    per_key: u32,
}

struct Window<K> {
    started: Instant,
    total: u32,
    counts: HashMap<K, u32>,
}

impl<K: Eq + Hash> RateLimit<K> {
    pub fn new(total_limit: u32, per_key: u32) -> Self {
        Self {
            window: Mutex::new(Window {
                started: Instant::now(),
                total: 0,
                counts: HashMap::new(),
            }),
            total_limit,
            per_key,
        }
    }

    pub fn check(&self, key: K) -> Result<(), (StatusCode, ErrorResponse)> {
        let mut window = self.window.lock().expect("rate limiter lock");
        if window.started.elapsed() >= Duration::from_secs(60) {
            window.started = Instant::now();
            window.total = 0;
            window.counts.clear();
        }
        if window.total >= self.total_limit {
            return Err(too_many_requests());
        }
        let count = window.counts.entry(key).or_default();
        if *count >= self.per_key {
            return Err(too_many_requests());
        }
        *count += 1;
        window.total += 1;
        Ok(())
    }
}

pub struct PasswordWork {
    permits: Arc<Semaphore>,
}

impl Default for PasswordWork {
    fn default() -> Self {
        Self {
            permits: Arc::new(Semaphore::new(2)),
        }
    }
}

pub fn valid_password(password: &str) -> bool {
    password.len() <= 128 && password.chars().count() >= 8
}

impl PasswordWork {
    async fn run<T: Send + 'static>(
        &self,
        task: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
    ) -> Result<T, (StatusCode, ErrorResponse)> {
        let permit = self
            .permits
            .clone()
            .try_acquire_owned()
            .map_err(|_| too_many_requests())?;
        // Keep the permit in the blocking task even if the client disconnects.
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            task()
        })
        .await;
        match result {
            Ok(Ok(value)) => Ok(value),
            _ => {
                tracing::error!("Password processing failed");
                Err(api_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "Password processing failed",
                ))
            }
        }
    }

    pub async fn hash(&self, password: String) -> Result<String, (StatusCode, ErrorResponse)> {
        if !valid_password(&password) {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "Password must be at least 8 characters and at most 128 bytes",
            ));
        }
        self.run(move || {
            let salt = SaltString::encode_b64(&db::random_bytes::<16>()?)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            let hash = Argon2::default()
                .hash_password(password.as_bytes(), &salt)
                .map_err(|error| anyhow::anyhow!("{error}"))?;
            Ok(hash.to_string())
        })
        .await
    }

    pub async fn verify(
        &self,
        password: String,
        hash: String,
    ) -> Result<bool, (StatusCode, ErrorResponse)> {
        if !valid_password(&password) {
            return Ok(false);
        }
        self.run(move || {
            let hash = PasswordHash::new(&hash).map_err(|error| anyhow::anyhow!("{error}"))?;
            match Argon2::default().verify_password(password.as_bytes(), &hash) {
                Ok(()) => Ok(true),
                Err(Error::Password) => Ok(false),
                Err(error) => Err(anyhow::anyhow!("{error}")),
            }
        })
        .await
    }
}

fn too_many_requests() -> (StatusCode, ErrorResponse) {
    api_error(
        StatusCode::TOO_MANY_REQUESTS,
        "Too many requests. Please try again shortly.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn password_work_rejects_new_jobs_when_both_slots_are_busy() {
        let work = PasswordWork::default();
        let reserved = work.permits.try_acquire_many(2).unwrap();
        let error = work.hash("test password".into()).await.unwrap_err();
        assert_eq!(error.0, StatusCode::TOO_MANY_REQUESTS);
        drop(reserved);
        assert!(work.hash("test password".into()).await.is_ok());
    }

    #[test]
    fn password_limits_count_characters_and_bytes() {
        assert!(valid_password(&"🚀".repeat(32)));
        assert!(!valid_password(&"🚀".repeat(33)));
        assert!(!valid_password(&"🚀".repeat(7)));
        assert!(valid_password("aaaaaaaa"));
    }
}
