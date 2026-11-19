use super::*;
use axum::body::to_bytes;
use tower::ServiceExt;

async fn state() -> AppState {
    AppState {
        db: setup_database(":memory:").await.unwrap(),
        base_url: "https://qkgo.de".into(),
        altcha_secret: "test-secret".into(),
        security: Default::default(),
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

pub(super) async fn request(app: Router, path: &str) -> Response {
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
            ..Default::default()
        },
        || "a".repeat(21),
        Some(verify_altcha(&state.altcha_secret, &payload).unwrap()),
        None,
        None,
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
        security: Default::default(),
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
            ..Default::default()
        },
        None,
        None,
    )
    .await
    .ok()
    .unwrap();
    let response = request(build_router(state), &format!("/{}", link.short_code)).await;
    assert_eq!(response.status(), StatusCode::GONE);
    assert!(!response.headers().contains_key(header::LOCATION));
}

#[tokio::test]
async fn concurrent_gets_share_a_quota_and_head_does_not_spend_it() {
    let state = state().await;
    let link = create_link(
        &state,
        CreateUrlRequest {
            url: "https://example.com".into(),
            max_visits: Some(2),
            ..Default::default()
        },
        None,
        None,
    )
    .await
    .ok()
    .unwrap();
    let app = build_router(state.clone());
    let path = format!("/{}", link.short_code);
    let head = app
        .clone()
        .oneshot(
            Request::builder()
                .method("HEAD")
                .uri(&path)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(head.status(), StatusCode::FOUND);
    assert!(to_bytes(head.into_body(), 1).await.unwrap().is_empty());
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..12 {
        let (app, path) = (app.clone(), path.clone());
        tasks.spawn(async move { request(app, &path).await });
    }
    let mut redirects = 0;
    while let Some(response) = tasks.join_next().await {
        let response = response.unwrap();
        if response.status() == StatusCode::FOUND {
            redirects += 1;
        } else {
            assert_eq!(response.status(), StatusCode::GONE);
            assert!(!response.headers().contains_key(header::LOCATION));
        }
    }
    assert_eq!(redirects, 2);
    let count: i64 = sqlx::query_scalar("SELECT visit_count FROM urls WHERE short_code = ?")
        .bind(link.short_code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(count, 2);
}

async fn form_page(response: Response) -> (String, String, String) {
    let cookie = response.headers()[header::SET_COOKIE]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_string();
    let body = html_body(response).await;
    let token = input_value(&body, "name=\"authenticity_token\" value=\"").to_owned();
    (cookie, token, body)
}

async fn html_body(response: Response) -> String {
    String::from_utf8(
        to_bytes(response.into_body(), 100_000)
            .await
            .unwrap()
            .to_vec(),
    )
    .unwrap()
}

fn input_value<'a>(body: &'a str, prefix: &str) -> &'a str {
    body.split_once(prefix)
        .unwrap()
        .1
        .split('"')
        .next()
        .unwrap()
}

fn solve_form(body: &str) -> String {
    let encoded = input_value(body, "challenge=\"data:application/json;base64,");
    let challenge: altcha_lib_rs::Challenge =
        serde_json::from_slice(&BASE64_STANDARD.decode(encoded).unwrap()).unwrap();
    let number = altcha_lib_rs::solve_challenge(
        &challenge.challenge,
        &challenge.salt,
        Some(challenge.algorithm),
        Some(challenge.maxnumber),
        0,
    )
    .unwrap();
    BASE64_STANDARD.encode(
        serde_json::to_vec(&altcha_lib_rs::Payload {
            algorithm: challenge.algorithm,
            challenge: challenge.challenge,
            number,
            salt: challenge.salt,
            signature: challenge.signature,
            took: None,
        })
        .unwrap(),
    )
}

async fn form_post(
    app: &Router,
    path: &str,
    cookie: &str,
    csrf: &str,
    proof: &str,
    fields: &[(&str, &str)],
) -> Response {
    let body: String = {
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("authenticity_token", csrf)
            .append_pair("altcha", proof);
        form.extend_pairs(fields.iter().copied());
        form.finish()
    };
    app.clone()
        .oneshot(
            Request::builder()
                .uri(path)
                .method("POST")
                .header(header::COOKIE, cookie)
                .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap()
}

#[tokio::test]
async fn password_page_requires_csrf_and_fresh_captcha_then_issues_one_redirect() {
    let state = state().await;
    let link = create_link(
        &state,
        CreateUrlRequest {
            url: "https://example.com/private".into(),
            max_visits: Some(1),
            password: Some("密碼 éü! xyz".into()),
            ..Default::default()
        },
        None,
        None,
    )
    .await
    .unwrap();
    let hash: String = sqlx::query_scalar("SELECT password_hash FROM urls WHERE short_code = ?")
        .bind(&link.short_code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert!(hash.starts_with("$argon2id$"));
    assert!(!hash.contains("密碼"));
    assert_ne!(
        hash,
        state
            .security
            .password_work
            .hash("密碼 éü! xyz".into())
            .await
            .unwrap()
    );

    let app = build_router(state);
    let path = format!("/{}", link.short_code);
    let page = request(app.clone(), &path).await;
    assert_eq!(page.status(), StatusCode::OK);
    assert!(!page.headers().contains_key(header::LOCATION));
    let (cookie, csrf, html) = form_page(page).await;
    assert!(!html.contains("https://example.com/private"));
    let proof = solve_form(&html);
    let correct = [("password", "密碼 éü! xyz")];
    let wrong = [("password", "wrong password")];
    assert_eq!(
        form_post(&app, &path, &cookie, "wrong", &proof, &correct)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        form_post(&app, &path, &cookie, &csrf, "invalid", &correct)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let retry = form_post(&app, &path, &cookie, &csrf, &proof, &wrong).await;
    assert_eq!(retry.status(), StatusCode::UNAUTHORIZED);
    assert!(!retry.headers().contains_key(header::LOCATION));
    assert_eq!(
        form_post(&app, &path, &cookie, &csrf, &proof, &correct)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let (cookie, csrf, html) = form_page(retry).await;
    let response = form_post(&app, &path, &cookie, &csrf, &solve_form(&html), &correct).await;
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(
        response.headers()[header::LOCATION],
        "https://example.com/private"
    );
    assert!(!response.headers().contains_key(header::SET_COOKIE));
    assert_eq!(request(app, &path).await.status(), StatusCode::GONE);
}

#[tokio::test]
async fn password_attempts_are_limited_per_link() {
    let state = state().await;
    let link = create_link(
        &state,
        CreateUrlRequest {
            url: "https://example.com".into(),
            password: Some("test password".into()),
            ..Default::default()
        },
        None,
        None,
    )
    .await
    .unwrap();
    let app = build_router(state.clone());
    let path = format!("/{}", link.short_code);
    let (cookie, csrf, _) = form_page(request(app.clone(), &path).await).await;
    let expired = solution(
        &state.altcha_secret,
        Some(Utc::now() - chrono::TimeDelta::seconds(1)),
    );
    assert_eq!(
        form_post(
            &app,
            &path,
            &cookie,
            &csrf,
            &expired,
            &[("password", "test password")]
        )
        .await
        .status(),
        StatusCode::BAD_REQUEST
    );
    for i in 0..11 {
        let proof = fresh_solution(&state);
        let response = form_post(
            &app,
            &path,
            &cookie,
            &csrf,
            &proof,
            &[("password", "wrong")],
        )
        .await;
        assert_eq!(
            response.status(),
            if i < 10 {
                StatusCode::UNAUTHORIZED
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
}

fn fresh_solution(state: &AppState) -> String {
    solution(
        &state.altcha_secret,
        Some(Utc::now() + chrono::TimeDelta::minutes(5)),
    )
}

#[tokio::test]
async fn edit_token_lookup_and_save_require_fresh_proofs_and_never_echo_the_token() {
    let state = state().await;
    let link = create_link(
        &state,
        CreateUrlRequest {
            url: "https://example.com/old".into(),
            expires_at: Some(Utc::now().timestamp() - 60),
            ..Default::default()
        },
        None,
        None,
    )
    .await
    .unwrap();
    let other = shorten_url(state.clone(), "https://example.com/other".into())
        .await
        .unwrap();
    assert_ne!(link.edit_token, other.edit_token);
    let hash: String = sqlx::query_scalar("SELECT edit_token_hash FROM urls WHERE short_code = ?")
        .bind(&link.short_code)
        .fetch_one(&state.db)
        .await
        .unwrap();
    assert_eq!(hash, db::hash_key(&link.edit_token));
    assert_ne!(hash, link.edit_token);

    let app = build_router(state.clone());
    let start = request(app.clone(), "/edit").await;
    assert_eq!(start.status(), StatusCode::OK);
    let (cookie, csrf, html) = form_page(start).await;
    let proof = solve_form(&html);
    let lookup = [("action", "lookup"), ("edit_token", &link.edit_token)];
    assert_eq!(
        form_post(&app, "/edit", &cookie, "wrong", &proof, &lookup)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        form_post(&app, "/edit", &cookie, &csrf, "wrong", &lookup)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    let found = form_post(&app, "/edit", &cookie, &csrf, &proof, &lookup).await;
    assert_eq!(found.status(), StatusCode::OK);
    assert_eq!(found.headers()[header::CACHE_CONTROL], "no-store");
    assert!(
        !found
            .headers()
            .values()
            .any(|value| value.to_str().unwrap_or("").contains(&link.edit_token))
    );
    let (cookie, csrf, html) = form_page(found).await;
    assert!(html.contains("https://example.com/old"));
    assert!(!html.contains(&link.edit_token));
    assert!(!html.contains(&hash));

    let mut save = [
        ("action", "save"),
        ("edit_token", other.edit_token.as_str()),
        ("short_code", &link.short_code),
        ("url", "https://example.com/new"),
        ("expires_at", ""),
        ("max_visits", "3"),
        ("password_action", "set"),
        ("password", "fixture 8Zy!X"),
    ];
    assert_eq!(
        form_post(&app, "/edit", &cookie, &csrf, &proof, &save)
            .await
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        form_post(
            &app,
            "/edit",
            &cookie,
            &csrf,
            &fresh_solution(&state),
            &save
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    save[1].1 = &link.edit_token;
    let save_proof = solve_form(&html);
    assert_eq!(
        form_post(&app, "/edit", &cookie, "wrong", &save_proof, &save)
            .await
            .status(),
        StatusCode::FORBIDDEN
    );
    let saved = form_post(&app, "/edit", &cookie, &csrf, &save_proof, &save).await;
    assert_eq!(saved.status(), StatusCode::OK);
    let (_, _, html) = form_page(saved).await;
    assert!(html.contains("Link settings saved."));
    assert!(html.contains("https://example.com/new"));
    assert!(!html.contains(&link.edit_token));
    assert!(!html.contains("fixture 8Zy!X"));
    let response = request(app.clone(), &format!("/{}", link.short_code)).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert!(html_body(response).await.contains("Password required"));

    db::revoke_link(&state.db, &link.short_code, "abuse")
        .await
        .unwrap();
    assert_eq!(
        form_post(
            &app,
            "/edit",
            &cookie,
            &csrf,
            &fresh_solution(&state),
            &lookup
        )
        .await
        .status(),
        StatusCode::GONE
    );
    assert_eq!(
        form_post(
            &app,
            "/edit",
            &cookie,
            &csrf,
            &fresh_solution(&state),
            &save
        )
        .await
        .status(),
        StatusCode::GONE
    );
}

#[tokio::test]
async fn edit_token_guesses_are_rate_limited() {
    let state = state().await;
    let app = build_router(state.clone());
    let (cookie, csrf, _) = form_page(request(app.clone(), "/edit").await).await;
    let fields = [("action", "lookup"), ("edit_token", "invalid")];
    for i in 0..31 {
        let response = form_post(
            &app,
            "/edit",
            &cookie,
            &csrf,
            &fresh_solution(&state),
            &fields,
        )
        .await;
        assert_eq!(
            response.status(),
            if i < 30 {
                StatusCode::NOT_FOUND
            } else {
                StatusCode::TOO_MANY_REQUESTS
            }
        );
    }
}

async fn api_link(
    app: &Router,
    method: Method,
    path: &str,
    key: &str,
    body: Option<serde_json::Value>,
) -> Response {
    let mut request = Request::builder()
        .method(method)
        .uri(path)
        .header("X-API-Key", key);
    let body = if let Some(body) = body {
        request = request.header(header::CONTENT_TYPE, "application/json");
        Body::from(body.to_string())
    } else {
        Body::empty()
    };
    app.clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap()
}

async fn json_body(response: Response) -> serde_json::Value {
    serde_json::from_slice(&to_bytes(response.into_body(), 100_000).await.unwrap()).unwrap()
}

#[tokio::test]
async fn api_key_ownership_is_private_and_revoking_a_key_leaves_the_edit_token_valid() {
    use serde_json::json;

    let state = state().await;
    let (id, key) = db::create_key(&state.db, "owner").await.unwrap();
    let (_, other) = db::create_key(&state.db, "other").await.unwrap();
    let anonymous = shorten_url(state.clone(), "https://example.com/anonymous".into())
        .await
        .unwrap();
    let app = build_router(state.clone());

    let response = api_link(&app, Method::POST, "/api/v1/shorten", &key,
        Some(json!({"url": "https://example.com/original", "password": "API fixture 3k!", "max_visits": 2,
                    "expires_at": Utc::now().timestamp() + 3600}))).await;
    assert_eq!(response.status(), StatusCode::CREATED);
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    let created = json_body(response).await;
    let code = created["short_code"].as_str().unwrap();
    let edit_token = created["edit_token"].as_str().unwrap();
    let expected_owner: i64 =
        sqlx::query_scalar("SELECT created_by_api_key_id FROM urls WHERE short_code = ?")
            .bind(code)
            .fetch_one(&state.db)
            .await
            .unwrap();
    assert_eq!(expected_owner, id);

    let path = format!("/api/v1/links/{code}");
    let public_path = format!("/{code}");
    let owned = json_body(api_link(&app, Method::GET, &path, &key, None).await).await;
    assert_eq!(owned["has_password"], true);
    assert_eq!(owned["max_visits"], 2);
    assert!(owned["expires_at"].is_i64());
    assert!(owned["updated_at"].is_string());
    assert!(owned.get("edit_token").is_none());
    assert!(owned.get("password_hash").is_none());
    assert!(owned.get("created_by_api_key_id").is_none());
    assert_eq!(
        api_link(&app, Method::GET, &path, &other, None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &other,
            Some(json!({"max_visits": 1}))
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    let anonymous_path = format!("/api/v1/links/{}", anonymous.short_code);
    assert_eq!(
        api_link(&app, Method::GET, &anonymous_path, &key, None)
            .await
            .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api_link(
            &app,
            Method::PATCH,
            &anonymous_path,
            &key,
            Some(json!({"max_visits": 1}))
        )
        .await
        .status(),
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"created_by_api_key_id": 2}))
        )
        .await
        .status(),
        StatusCode::UNPROCESSABLE_ENTITY
    );

    for payload in [
        json!({"url": null}),
        json!({"url": "https://qkgo.de./self"}),
        json!({"url": "javascript:alert(1)"}),
        json!({"max_visits": 0}),
        json!({"password": "short"}),
        json!({"expires_at": i64::MAX}),
    ] {
        assert_eq!(
            api_link(&app, Method::PATCH, &path, &key, Some(payload))
                .await
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let patched = json_body(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"url": "https://example.com/new", "expires_at": 1})),
        )
        .await,
    )
    .await;
    assert_eq!(patched["original_url"], "https://example.com/new");
    assert_eq!(patched["expires_at"], 1);
    assert_eq!(patched["has_password"], true);
    assert_eq!(patched["max_visits"], 2);
    assert_eq!(
        request(app.clone(), &public_path).await.status(),
        StatusCode::GONE
    );

    let cleared = json_body(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"password": null, "expires_at": null, "max_visits": 1})),
        )
        .await,
    )
    .await;
    assert_eq!(cleared["has_password"], false);
    assert!(cleared["expires_at"].is_null());
    let redirect = request(app.clone(), &public_path).await;
    assert_eq!(redirect.status(), StatusCode::FOUND);
    assert_eq!(
        redirect.headers()[header::LOCATION],
        "https://example.com/new"
    );
    assert_eq!(
        request(app.clone(), &public_path).await.status(),
        StatusCode::GONE
    );

    let raised = json_body(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"max_visits": 2})),
        )
        .await,
    )
    .await;
    assert_eq!(raised["visit_count"], 1);
    assert_eq!(
        request(app.clone(), &public_path).await.status(),
        StatusCode::FOUND
    );
    assert_eq!(
        request(app.clone(), &public_path).await.status(),
        StatusCode::GONE
    );
    let unlimited = json_body(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"max_visits": null})),
        )
        .await,
    )
    .await;
    assert!(unlimited["max_visits"].is_null());
    assert_eq!(unlimited["visit_count"], 2);
    for _ in 0..2 {
        assert_eq!(
            request(app.clone(), &public_path).await.status(),
            StatusCode::FOUND
        );
    }
    let capped = json_body(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"max_visits": 2})),
        )
        .await,
    )
    .await;
    assert_eq!(capped["visit_count"], 2);
    assert_eq!(
        request(app.clone(), &public_path).await.status(),
        StatusCode::GONE
    );

    db::revoke_key(&state.db, id).await.unwrap();
    assert_eq!(
        api_link(&app, Method::GET, &path, &key, None)
            .await
            .status(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        api_link(
            &app,
            Method::PATCH,
            &path,
            &key,
            Some(json!({"max_visits": 3}))
        )
        .await
        .status(),
        StatusCode::UNAUTHORIZED
    );
    let (cookie, csrf, _) = form_page(request(app.clone(), "/edit").await).await;
    let edit = form_post(
        &app,
        "/edit",
        &cookie,
        &csrf,
        &fresh_solution(&state),
        &[
            ("action", "save"),
            ("short_code", code),
            ("edit_token", edit_token),
            ("max_visits", "3"),
        ],
    )
    .await;
    assert_eq!(edit.status(), StatusCode::OK);
    assert_eq!(request(app, &public_path).await.status(), StatusCode::FOUND);
}

#[tokio::test]
async fn api_rate_limit_is_shared_across_endpoints_for_each_key() {
    let state = state().await;
    let (_, key) = db::create_key(&state.db, "limited").await.unwrap();
    let (_, other) = db::create_key(&state.db, "other").await.unwrap();
    let app = build_router(state);
    for _ in 0..120 {
        assert_eq!(
            api_link(&app, Method::GET, "/api/v1/links/missing", &key, None)
                .await
                .status(),
            StatusCode::NOT_FOUND
        );
    }
    assert_eq!(
        api(app.clone(), Some(&key), "https://example.com")
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        api(app, Some(&other), "https://example.com").await.status(),
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn a_committing_admin_revocation_wins_over_a_waiting_patch() {
    let path = std::env::temp_dir().join(format!("quickgo-race-{}.db", rand::random::<u64>()));
    let pool = db::setup(path.to_str().unwrap()).await.unwrap();
    let state = AppState {
        db: pool.clone(),
        ..state().await
    };
    let (_, key) = db::create_key(&pool, "owner").await.unwrap();
    let app = build_router(state);
    let created = json_body(api(app.clone(), Some(&key), "https://example.com/before").await).await;
    let code = created["short_code"].as_str().unwrap();
    let edit_path = format!("/api/v1/links/{code}");

    let mut tx = pool.begin().await.unwrap();
    sqlx::query("UPDATE urls SET revoked_at = CURRENT_TIMESTAMP WHERE short_code = ?")
        .bind(code)
        .execute(&mut *tx)
        .await
        .unwrap();
    let patch = api_link(
        &app,
        Method::PATCH,
        &edit_path,
        &key,
        Some(serde_json::json!({"url": "https://example.com/after"})),
    );
    tokio::pin!(patch);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(50), &mut patch)
            .await
            .is_err()
    );
    tx.commit().await.unwrap();
    assert_eq!(patch.await.status(), StatusCode::GONE);
    assert_eq!(
        api_link(&app, Method::GET, &edit_path, &key, None)
            .await
            .status(),
        StatusCode::GONE
    );
    let url: String = sqlx::query_scalar("SELECT original_url FROM urls WHERE short_code = ?")
        .bind(code)
        .fetch_one(&pool)
        .await
        .unwrap();
    assert_eq!(url, "https://example.com/before");
    pool.close().await;
    std::fs::remove_file(path).unwrap();
}
