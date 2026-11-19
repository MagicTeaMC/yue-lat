use super::*;
use axum::body::to_bytes;
use tower::ServiceExt;

async fn state() -> AppState {
    AppState {
        db: setup_database(":memory:").await.unwrap(),
        base_url: "https://qkgo.de".into(),
        altcha_secret: "test-secret".into(),
    }
}

fn solution(secret: &str, expires: Option<chrono::DateTime<Utc>>) -> String {
    let challenge = altcha_lib_rs::create_challenge(ChallengeOptions {
        hmac_key: secret,
        number: Some(1),
        expires,
        ..Default::default()
    })
    .unwrap();
    let solution = altcha_lib_rs::Payload {
        algorithm: challenge.algorithm,
        challenge: challenge.challenge,
        number: 1,
        salt: challenge.salt,
        signature: challenge.signature,
        took: Some(10),
    };
    BASE64_STANDARD.encode(serde_json::to_vec(&solution).unwrap())
}

async fn request(app: Router, path: &str) -> Response {
    app.oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
        .await
        .unwrap()
}

async fn api(app: Router, key: Option<&str>, url: &str) -> Response {
    let mut builder = Request::builder()
        .method("POST")
        .uri("/api/v1/shorten")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(key) = key {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {key}"));
    }
    app.oneshot(
        builder
            .body(Body::from(serde_json::json!({"url": url}).to_string()))
            .unwrap(),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn api_keys_are_hashed_and_revocation_affects_the_running_router() {
    let state = state().await;
    let (id, key) = db::create_key(&state.db, "test-bot").await.unwrap();
    let hash: String = sqlx::query_scalar("SELECT key_hash FROM api_keys WHERE id = ?")
        .bind(id)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(hash, db::hash_key(&key));
    assert!(!hash.contains(&key));
    let app = build_router(state.clone());
    assert_eq!(
        api(app.clone(), None, "https://example.com").await.status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api(app.clone(), Some("incorrect"), "https://example.com")
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api(app.clone(), Some(&key), "https://example.com")
            .await
            .status(),
        StatusCode::CREATED
    );
    db::revoke_key(&state.db, id).await.unwrap();
    assert_eq!(
        api(app, Some(&key), "https://example.com").await.status(),
        StatusCode::UNAUTHORIZED
    );
}

#[tokio::test]
async fn revoked_link_has_html_410_no_location_and_no_cache() {
    let state = state().await;
    let created = shorten_url(state.clone(), "https://example.com/private".into())
        .await
        .ok()
        .unwrap();
    let app = build_router(state.clone());
    let path = format!("/{}", created.short_code);
    let response = request(app.clone(), &path).await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://example.com/private"
    );
    db::revoke_link(&state.db, &created.short_code, "private abuse details")
        .await
        .unwrap();
    db::revoke_link(&state.db, &created.short_code, "second reason")
        .await
        .unwrap();
    let reason: String = sqlx::query_scalar("SELECT revoke_reason FROM urls WHERE short_code = ?")
        .bind(&created.short_code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(reason, "private abuse details");
    let response = request(app, &path).await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert!(response.headers().get(header::LOCATION).is_none());
    let body = String::from_utf8(
        to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    assert!(body.contains("This link has been revoked"));
    assert!(!body.contains("private abuse details"));
    assert!(!body.contains("https://example.com/private"));
    assert!(db::revoke_link(&state.db, "missing", "test").await.is_err());
}

#[tokio::test]
async fn challenge_replay_uses_verified_identity_not_client_metadata() {
    let state = state().await;
    let payload = solution(
        &state.altcha_secret,
        Some(Utc::now() + chrono::TimeDelta::minutes(5)),
    );
    let challenge = verify_altcha(&state.altcha_secret, &payload).unwrap();
    assert!(
        shorten_url_with_challenge(
            state.clone(),
            "https://example.com/a".into(),
            Some(challenge)
        )
        .await
        .is_ok()
    );
    let mut changed: serde_json::Value =
        serde_json::from_slice(&BASE64_STANDARD.decode(&payload).unwrap()).unwrap();
    changed["took"] = serde_json::json!(100.5);
    let changed = BASE64_STANDARD.encode(serde_json::to_vec_pretty(&changed).unwrap());
    let challenge = verify_altcha(&state.altcha_secret, &changed).unwrap();
    let error = shorten_url_with_challenge(
        state.clone(),
        "https://example.com/b".into(),
        Some(challenge),
    )
    .await
    .err()
    .unwrap();
    assert_eq!(error.0, StatusCode::BAD_REQUEST);
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM urls")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn challenge_is_not_consumed_when_link_insert_fails() {
    let state = state().await;
    let payload = solution(
        &state.altcha_secret,
        Some(Utc::now() + chrono::TimeDelta::minutes(5)),
    );
    let result = store_url(
        &state,
        CreateUrlRequest {
            url: "https://example.com".into(),
            expires_at: None,
        },
        || "a".repeat(21),
        Some(verify_altcha(&state.altcha_secret, &payload).unwrap()),
    )
    .await;
    assert!(result.is_err());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM used_challenges")
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 0);
    assert!(
        shorten_url_with_challenge(
            state.clone(),
            "https://example.com".into(),
            Some(verify_altcha(&state.altcha_secret, &payload).unwrap())
        )
        .await
        .is_ok()
    );
}

#[test]
fn captcha_rejects_expired_missing_expiration_and_invalid_signature() {
    let secret = "test-secret";
    assert!(
        verify_altcha(
            secret,
            &solution(secret, Some(Utc::now() - chrono::TimeDelta::minutes(1)))
        )
        .is_err()
    );
    assert!(verify_altcha(secret, &solution(secret, None)).is_err());
    assert!(
        verify_altcha(
            "wrong-secret",
            &solution(secret, Some(Utc::now() + chrono::TimeDelta::minutes(5)))
        )
        .is_err()
    );
    assert!(verify_altcha(secret, "not-base64").is_err());
}

#[tokio::test]
async fn reserved_paths_cannot_be_allocated_or_resolved_as_short_links() {
    let state = state().await;
    let mut codes = ["static", "HeAlTh", "Ab12Cd"].into_iter();
    let link = store_url_with_generator(&state, "https://example.com".into(), || {
        codes.next().unwrap().into()
    })
    .await
    .ok()
    .unwrap();
    assert_eq!(link.short_code, "Ab12Cd");
    // A legacy/manual row must not capture a reserved page.
    sqlx::query(
        "INSERT INTO urls (short_code, original_url) VALUES ('about', 'https://example.com')",
    )
    .execute(&state.db)
    .await
    .unwrap();
    let app = build_router(state);
    assert_eq!(
        request(app.clone(), "/about").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(app.clone(), "/api/v1").await.status(),
        StatusCode::OK
    );
    assert_eq!(
        request(app.clone(), "/api-key/create").await.status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(app, "/link/revoke").await.status(),
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn destinations_are_normalized_and_credentials_and_self_links_rejected() {
    let state = state().await;
    for url in [
        "https://user:pass@example.com",
        "https://qkgo.de/Ab12Cd",
        "http://qkgo.de:8080/a",
        "javascript:alert(1)",
    ] {
        assert!(shorten_url(state.clone(), url.into()).await.is_err());
    }
    let link = shorten_url(state, "HTTPS://EXAMPLE.COM".into())
        .await
        .ok()
        .unwrap();
    assert_eq!(link.original_url, "https://example.com/");
}

#[tokio::test]
async fn legacy_migration_preserves_links_and_replay_survives_reopen() {
    let path = std::env::temp_dir().join(format!(
        "quickgo-{}-{}.db",
        std::process::id(),
        rand::random::<u64>()
    ));
    let path_str = path.to_str().unwrap();
    let legacy = db::open(path_str, true).await.unwrap();
    sqlx::raw_sql(include_str!("../migrations/0001_existing_urls.sql"))
        .execute(&legacy)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO urls (short_code, original_url) VALUES ('Ab12', 'https://example.com/old')",
    )
    .execute(&legacy)
    .await
    .unwrap();
    legacy.close().await;
    let pool = db::setup(path_str).await.unwrap();
    let state = AppState {
        db: pool.clone(),
        base_url: "https://qkgo.de".into(),
        altcha_secret: "test-secret".into(),
    };
    let payload = solution(
        &state.altcha_secret,
        Some(Utc::now() + chrono::TimeDelta::minutes(5)),
    );
    let first = verify_altcha(&state.altcha_secret, &payload).unwrap();
    let second = verify_altcha(&state.altcha_secret, &payload).unwrap();
    let (a, b) = tokio::join!(
        shorten_url_with_challenge(state.clone(), "https://example.com/a".into(), Some(first)),
        shorten_url_with_challenge(state.clone(), "https://example.com/b".into(), Some(second)),
    );
    assert_eq!(usize::from(a.is_ok()) + usize::from(b.is_ok()), 1);
    let failed = a.err().or_else(|| b.err()).unwrap();
    assert_eq!(failed.0, StatusCode::BAD_REQUEST);
    pool.close().await;
    let reopened = db::setup(path_str).await.unwrap();
    let state = AppState {
        db: reopened.clone(),
        ..state
    };
    assert!(
        shorten_url_with_challenge(
            state.clone(),
            "https://example.com/c".into(),
            Some(verify_altcha(&state.altcha_secret, &payload).unwrap())
        )
        .await
        .is_err()
    );
    let response = request(build_router(state), "/Ab12").await;
    assert_eq!(response.status(), StatusCode::FOUND);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://example.com/old"
    );
    db::check(path_str).await.unwrap();
    reopened.close().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn form_checks_csrf_and_captcha_and_sets_no_store() {
    let state = state().await;
    let app = build_router(state.clone());
    let response = request(app.clone(), "/").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let cookie = response
        .headers()
        .get(header::SET_COOKIE)
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    let html = String::from_utf8(
        to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap();
    let token = html
        .split("name=\"authenticity_token\" value=\"")
        .nth(1)
        .unwrap()
        .split('"')
        .next()
        .unwrap();
    let payload = solution(
        &state.altcha_secret,
        Some(Utc::now() + chrono::TimeDelta::minutes(5)),
    );
    async fn submit(app: Router, cookie: &str, token: &str, payload: &str) -> Response {
        let body = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("url", "https://example.com/form")
            .append_pair("authenticity_token", token)
            .append_pair("altcha", payload)
            .finish();
        app.oneshot(
            Request::builder()
                .method("POST")
                .uri("/")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
    }
    assert_eq!(
        submit(app.clone(), &cookie, "wrong-token", &payload)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        submit(app.clone(), &cookie, token, "invalid")
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        submit(app.clone(), &cookie, token, &payload).await.status(),
        StatusCode::OK
    );
    assert_eq!(
        submit(app, &cookie, token, &payload).await.status(),
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn expired_links_return_410_without_location() {
    let state = state().await;
    let link = create_link(
        &state,
        CreateUrlRequest {
            url: "https://example.com".into(),
            expires_at: Some(Utc::now().timestamp() - 1),
        },
        None,
    )
    .await
    .ok()
    .unwrap();
    let response = request(build_router(state), &format!("/{}", link.short_code)).await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert!(!response.headers().contains_key(header::LOCATION));
}
