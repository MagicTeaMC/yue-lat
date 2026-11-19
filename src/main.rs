use altcha_lib_rs::ChallengeOptions;
use anyhow::Result;
use askama::Template;
use axum::{
    Form, Json, Router,
    body::Body,
    extract::{DefaultBodyLimit, Path, State},
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use http::Method;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use tracing_subscriber;
use url::Url;

const MAX_URL_LENGTH: usize = 2048;
const MAX_SHORT_CODE_LENGTH: usize = 20;
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

#[derive(Template)]
#[template(path = "api_docs.html")]
struct ApiDocsTemplate {
    base_url: String,
}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    base_url: String,
    authenticity_token: String,
    altcha_challenge: String,
}

#[derive(Template)]
#[template(path = "success.html")]
struct SuccessTemplate {
    short_url: String,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    error_message: String,
}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    base_url: String,
    api_keys: Vec<String>,
    altcha_secret: String,
}

struct HtmlError {
    status: StatusCode,
    message: String,
}

impl IntoResponse for HtmlError {
    fn into_response(self) -> Response {
        let template = ErrorTemplate {
            error_message: self.message,
        };

        match template.render() {
            Ok(html) => (self.status, Html(html)).into_response(),
            Err(e) => {
                tracing::error!("Failed to render error template: {}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
            }
        }
    }
}

async fn validate_api_key(
    State(state): State<AppState>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let api_key = req
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.headers()
                .get("Authorization")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.strip_prefix("Bearer "))
        });

    match api_key {
        Some(key) if state.api_keys.contains(&key.to_string()) => Ok(next.run(req).await),
        Some(_) => {
            tracing::warn!("Invalid API key attempted");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Invalid API key".to_string(),
                }),
            ))
        }
        None => {
            tracing::warn!("Missing API key");
            Err((
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "API key required. Please provide X-API-Key header or Authorization: Bearer <key>".to_string(),
                }),
            ))
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(dotenvy::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let port: u16 = dotenvy::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a valid number");

    let base_url = normalize_base_url(
        &dotenvy::var("BASE_URL").unwrap_or_else(|_| "https://qkgo.de".to_string()),
    )?;

    let api_keys_str = dotenvy::var("API_KEYS").expect("API_KEYS environment variable must be set");

    let api_keys: Vec<String> = api_keys_str
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if api_keys.is_empty() {
        panic!("At least one API key must be configured in API_KEYS");
    }

    let altcha_secret = dotenvy::var("ALTCHA_SECRET").expect("ALTCHA_SECRET must be set");
    anyhow::ensure!(
        !altcha_secret.trim().is_empty(),
        "ALTCHA_SECRET must not be empty"
    );
    tracing::info!("Loaded {} API key(s)", api_keys.len());
    tracing::info!("Using base URL: {}", base_url);

    let database_path = dotenvy::var("DATABASE_PATH").unwrap_or_else(|_| "urls.db".to_string());
    let db = setup_database(&database_path).await?;

    let app_state = AppState {
        db,
        base_url,
        api_keys,
        altcha_secret,
    };

    let static_service = ServeDir::new("static").append_index_html_on_directories(false);

    let public_routes = Router::new()
        .route("/", get(root).post(create_url_form))
        .route("/api/v1", get(api_docs))
        .route("/favicon.ico", get(favicon))
        .route("/{short_code}", get(redirect_url))
        .nest_service("/static", static_service);

    let api_routes = Router::new()
        .route("/api/v1/shorten", post(create_url))
        .layer(middleware::from_fn_with_state(
            app_state.clone(),
            validate_api_key,
        ));

    let app = Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(MAX_REQUEST_SIZE))
                .layer(
                    CorsLayer::new()
                        .allow_headers(Any)
                        .allow_methods([Method::GET, Method::POST]),
                )
                .layer(CsrfLayer::new(CsrfConfig::default())),
        )
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    tracing::info!("URL Shortener listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn setup_database(path: &str) -> Result<SqlitePool, sqlx::Error> {
    let options = if path == ":memory:" {
        "sqlite::memory:".parse::<sqlx::sqlite::SqliteConnectOptions>()?
    } else {
        sqlx::sqlite::SqliteConnectOptions::new().filename(path)
    };
    let pool = SqlitePool::connect_with(
        options
            .create_if_missing(true)
            .pragma("journal_mode", "WAL")
            .pragma("synchronous", "NORMAL")
            .pragma("cache_size", "1000")
            .pragma("foreign_keys", "true")
            .pragma("temp_store", "memory"),
    )
    .await?;

    sqlx::query(
        "CREATE TABLE IF NOT EXISTS urls (
            short_code TEXT PRIMARY KEY CHECK(length(short_code) <= 20),
            original_url TEXT NOT NULL CHECK(length(original_url) <= 2048),
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await?;

    tracing::info!("Database pool initialized with {} connections", pool.size());
    Ok(pool)
}

fn normalize_base_url(value: &str) -> Result<String> {
    let parsed = Url::parse(value.trim())?;
    anyhow::ensure!(
        matches!(parsed.scheme(), "http" | "https")
            && parsed.host_str().is_some()
            && parsed.username().is_empty()
            && parsed.password().is_none()
            && parsed.path() == "/"
            && parsed.query().is_none()
            && parsed.fragment().is_none(),
        "BASE_URL must be an HTTP(S) origin without credentials, path, query, or fragment"
    );
    Ok(parsed.as_str().trim_end_matches('/').to_string())
}

fn validate_url_length(url: &str) -> Result<(), String> {
    if url.len() > MAX_URL_LENGTH {
        return Err(format!(
            "URL too long. Maximum length is {} characters",
            MAX_URL_LENGTH
        ));
    }
    Ok(())
}

fn validate_short_code_length(short_code: &str) -> Result<(), String> {
    if short_code.len() > MAX_SHORT_CODE_LENGTH {
        return Err(format!(
            "Short code too long. Maximum length is {} characters",
            MAX_SHORT_CODE_LENGTH
        ));
    }
    Ok(())
}

fn validate_url_format(url: &str) -> Result<(), String> {
    match Url::parse(url) {
        Ok(parsed) => {
            if parsed.scheme() != "http" && parsed.scheme() != "https" {
                return Err("URL scheme must be http or https".to_string());
            }
            Ok(())
        }
        Err(e) => Err(format!("Invalid URL: {}", e)),
    }
}

async fn favicon() -> Response {
    let svg_favicon = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="#007bff">
        <path d="M4.5 1A1.5 1.5 0 0 0 3 2.5v3A1.5 1.5 0 0 0 4.5 7h7A1.5 1.5 0 0 0 13 5.5v-3A1.5 1.5 0 0 0 11.5 1h-7z"/>
        <path d="M11.5 9A1.5 1.5 0 0 0 10 10.5v3A1.5 1.5 0 0 0 11.5 15h3A1.5 1.5 0 0 0 16 13.5v-3A1.5 1.5 0 0 0 14.5 9h-3z"/>
        <path d="M8.854 8.146a.5.5 0 0 0-.708.708l1.5 1.5a.5.5 0 0 0 .708-.708l-1.5-1.5z"/>
    </svg>"##;
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/svg+xml")
        .header(header::CACHE_CONTROL, "public, max-age=604800")
        .body(svg_favicon.into())
        .unwrap()
}

async fn root(
    token: CsrfToken,
    State(app_state): State<AppState>,
) -> Result<(CsrfToken, Html<String>), HtmlError> {
    let challenge = altcha_lib_rs::create_challenge(ChallengeOptions {
        hmac_key: &app_state.altcha_secret,
        max_number: Some(100_000),
        expires: Some(Utc::now() + chrono::TimeDelta::minutes(5)),
        ..Default::default()
    })
    .map_err(|e| {
        tracing::error!("Failed to create ALTCHA challenge: {:?}", e);
        HtmlError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Failed to generate challenge. Please try again.".to_string(),
        }
    })?;

    let challenge_json = serde_json::to_string(&challenge).map_err(|e| {
        tracing::error!("Failed to serialize challenge: {}", e);
        HtmlError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Failed to generate challenge. Please try again.".to_string(),
        }
    })?;

    let challenge_base64 = BASE64_STANDARD.encode(challenge_json.as_bytes());

    let template = IndexTemplate {
        base_url: app_state.base_url.clone(),
        authenticity_token: token.authenticity_token().unwrap(),
        altcha_challenge: challenge_base64,
    };

    match template.render() {
        Ok(html) => Ok((token, Html(html))),
        Err(e) => {
            tracing::error!("Template rendering error: {}", e);
            Err(HtmlError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Failed to load page. Please try again later.".to_string(),
            })
        }
    }
}

async fn api_docs(State(app_state): State<AppState>) -> Result<Html<String>, HtmlError> {
    let template = ApiDocsTemplate {
        base_url: app_state.base_url,
    };
    match template.render() {
        Ok(html) => Ok(Html(html)),
        Err(e) => {
            tracing::error!("Template rendering error: {}", e);
            Err(HtmlError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Failed to load page. Please try again later.".to_string(),
            })
        }
    }
}

async fn create_url(
    State(app_state): State<AppState>,
    Json(payload): Json<CreateUrlRequest>,
) -> Result<(StatusCode, Json<UrlResponse>), (StatusCode, Json<ErrorResponse>)> {
    let result = shorten_url(app_state, payload.url).await;
    match result {
        Ok(response) => {
            tracing::info!("Created short URL: {}", response.short_code);
            Ok((StatusCode::CREATED, Json(response)))
        }
        Err((status, error_response)) => {
            tracing::warn!("Failed to create short URL: {}", error_response.error);
            Err((status, Json(error_response)))
        }
    }
}

async fn create_url_form(
    token: CsrfToken,
    State(app_state): State<AppState>,
    Form(payload): Form<CreateUrlFormRequest>,
) -> Result<Html<String>, HtmlError> {
    if token.verify(&payload.authenticity_token).is_err() {
        tracing::warn!("CSRF token verification failed");
        return Err(HtmlError {
            status: StatusCode::FORBIDDEN,
            message: "Invalid security token. Please refresh the page and try again.".to_string(),
        });
    }

    let verification = verify_altcha(&app_state.altcha_secret, &payload.altcha).await;
    if let Err(error_message) = verification {
        tracing::warn!("ALTCHA verification failed: {}", error_message);
        return Err(HtmlError {
            status: StatusCode::BAD_REQUEST,
            message: error_message,
        });
    }

    let result = shorten_url(app_state, payload.url).await;
    match result {
        Ok(response) => {
            tracing::info!("Created short URL via form: {}", response.short_code);
            let success_template = SuccessTemplate {
                short_url: response.short_url,
            };
            match success_template.render() {
                Ok(html) => Ok(Html(html)),
                Err(e) => {
                    tracing::error!("Template rendering error: {}", e);
                    Err(HtmlError {
                        status: StatusCode::INTERNAL_SERVER_ERROR,
                        message: "Failed to generate success page. Please try again.".to_string(),
                    })
                }
            }
        }
        Err((status, error_response)) => {
            tracing::warn!(
                "Failed to create short URL via form: {}",
                error_response.error
            );
            Err(HtmlError {
                status,
                message: error_response.error,
            })
        }
    }
}

async fn shorten_url(
    app_state: AppState,
    url: String,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    if let Err(error) = validate_url_length(&url) {
        return Err((StatusCode::BAD_REQUEST, ErrorResponse { error }));
    }
    if url.trim().is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            ErrorResponse {
                error: "URL cannot be empty".to_string(),
            },
        ));
    }
    let url = url.trim().to_string();
    if let Err(error) = validate_url_format(&url) {
        return Err((StatusCode::BAD_REQUEST, ErrorResponse { error }));
    }
    store_url_with_generator(&app_state, url, generate_short_code).await
}

async fn store_url_with_generator(
    app_state: &AppState,
    url: String,
    mut generate: impl FnMut() -> String,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    for _ in 0..10 {
        let short_code = generate();
        match sqlx::query("INSERT INTO urls (short_code, original_url) VALUES (?, ?)")
            .bind(&short_code)
            .bind(&url)
            .execute(&app_state.db)
            .await
        {
            Ok(_) => {
                return Ok(UrlResponse {
                    original_url: url,
                    short_url: format!("{}/{}", app_state.base_url, short_code),
                    short_code,
                });
            }
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => continue,
            Err(error) => {
                tracing::error!("Database insert failed: {}", error);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    ErrorResponse {
                        error: "Database error occurred. Please try again.".to_string(),
                    },
                ));
            }
        }
    }
    Err((
        StatusCode::INTERNAL_SERVER_ERROR,
        ErrorResponse {
            error: "Unable to generate unique short code. Please try again.".to_string(),
        },
    ))
}

async fn redirect_url(
    Path(short_code): Path<String>,
    State(app_state): State<AppState>,
) -> Result<Redirect, HtmlError> {
    if let Err(error) = validate_short_code_length(&short_code) {
        tracing::warn!("Short code validation failed in redirect: {}", error);
        return Err(HtmlError {
            status: StatusCode::BAD_REQUEST,
            message: "Invalid short code format.".to_string(),
        });
    }
    if !short_code.chars().all(|c| c.is_alphanumeric()) {
        tracing::warn!("Invalid characters in short code: {}", short_code);
        return Err(HtmlError {
            status: StatusCode::BAD_REQUEST,
            message: "Invalid short code format.".to_string(),
        });
    }
    let result = sqlx::query("SELECT original_url FROM urls WHERE short_code = ?")
        .bind(&short_code)
        .fetch_optional(&app_state.db)
        .await;
    match result {
        Ok(Some(row)) => {
            let original_url: String = row.get("original_url");
            tracing::debug!("Redirecting {}", short_code);
            Ok(Redirect::permanent(&original_url))
        }
        Ok(None) => {
            tracing::warn!("Short code not found: {}", short_code);
            Err(HtmlError {
                status: StatusCode::NOT_FOUND,
                message: format!(
                    "Short URL '{}' not found. It may have been mistyped or doesn't exist.",
                    short_code
                ),
            })
        }
        Err(e) => {
            tracing::error!("Database error: {}", e);
            Err(HtmlError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Database error occurred. Please try again later.".to_string(),
            })
        }
    }
}

fn generate_short_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const CODE_LENGTH: usize = 6;

    let mut rng = rand::rng();
    (0..CODE_LENGTH)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

async fn verify_altcha(secret: &str, payload: &str) -> Result<(), String> {
    if payload.is_empty() {
        return Err("Missing CAPTCHA response".to_string());
    }

    let decoded_payload = BASE64_STANDARD
        .decode(payload)
        .map_err(|_| format!("CAPTCHA verification failed"))?;

    let string_payload = std::str::from_utf8(&decoded_payload)
        .map_err(|_| format!("CAPTCHA verification failed"))?;

    altcha_lib_rs::verify_json_solution(string_payload, secret, true)
        .map_err(|_| format!("CAPTCHA verification failed"))?;

    Ok(())
}

#[derive(Deserialize)]
struct CreateUrlRequest {
    url: String,
}

#[derive(Deserialize)]
struct CreateUrlFormRequest {
    url: String,
    authenticity_token: String,
    altcha: String,
}

#[derive(Serialize)]
struct UrlResponse {
    original_url: String,
    short_code: String,
    short_url: String,
}

#[derive(Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn state() -> AppState {
        AppState {
            db: setup_database(":memory:").await.unwrap(),
            base_url: "https://qkgo.de".into(),
            api_keys: vec!["test-key".into()],
            altcha_secret: "test-secret".into(),
        }
    }

    #[test]
    fn base_url_accepts_origins_and_rejects_unsafe_components() {
        assert_eq!(
            normalize_base_url(" https://qkgo.de/ ").unwrap(),
            "https://qkgo.de"
        );
        assert_eq!(
            normalize_base_url("http://localhost:3000").unwrap(),
            "http://localhost:3000"
        );
        for invalid in [
            "javascript:alert(1)",
            "https://user:pass@example.com",
            "https://example.com/path",
            "https://example.com/?a=b",
            "https://example.com/#fragment",
        ] {
            assert!(normalize_base_url(invalid).is_err(), "accepted {invalid}");
        }
    }

    #[tokio::test]
    async fn collision_retries_without_overwriting_existing_link() {
        let state = state().await;
        sqlx::query("INSERT INTO urls (short_code, original_url) VALUES ('abcd', 'https://example.com/old')")
            .execute(&state.db).await.unwrap();
        let mut codes = ["abcd", "Ab12Cd"].into_iter();
        let response = store_url_with_generator(&state, "https://example.com/new".into(), || {
            codes.next().unwrap().into()
        })
        .await;
        assert!(response.is_ok());
        let response = response.ok().unwrap();
        assert_eq!(response.short_url, "https://qkgo.de/Ab12Cd");
        let row = sqlx::query("SELECT original_url FROM urls WHERE short_code = 'abcd'")
            .fetch_one(&state.db)
            .await
            .unwrap();
        assert_eq!(
            row.get::<String, _>("original_url"),
            "https://example.com/old"
        );
        let redirect = redirect_url(Path("abcd".into()), State(state)).await;
        assert!(redirect.is_ok());
        let response = redirect.ok().unwrap().into_response();
        assert_eq!(
            response.headers()[header::LOCATION],
            "https://example.com/old"
        );
    }

    #[tokio::test]
    async fn collisions_stop_after_ten_attempts_and_database_errors_do_not_retry() {
        let state = state().await;
        let mut attempts = 0;
        let first =
            store_url_with_generator(&state, "https://example.com".into(), || "abcdef".into())
                .await;
        assert!(first.is_ok());
        let result = store_url_with_generator(&state, "https://example.com/new".into(), || {
            attempts += 1;
            "abcdef".into()
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts, 10);
        state.db.close().await;
        attempts = 0;
        let result = store_url_with_generator(&state, "https://example.com".into(), || {
            attempts += 1;
            "ghijkl".into()
        })
        .await;
        assert!(result.is_err());
        assert_eq!(attempts, 1);
    }

    #[tokio::test]
    async fn new_links_use_six_characters_and_reject_non_web_urls() {
        let state = state().await;
        let result = shorten_url(state.clone(), "https://example.com/path?q=1".into()).await;
        assert!(result.is_ok());
        let response = result.ok().unwrap();
        assert_eq!(response.short_code.len(), 6);
        assert!(
            response
                .short_code
                .bytes()
                .all(|c| c.is_ascii_alphanumeric())
        );
        assert_eq!(
            response.short_url,
            format!("https://qkgo.de/{}", response.short_code)
        );
        assert!(
            shorten_url(state, "javascript:alert(1)".into())
                .await
                .is_err()
        );
    }

    #[test]
    fn documentation_and_homepage_follow_configured_origin() {
        let base_url = "https://links.example.com:8443";
        let docs = ApiDocsTemplate {
            base_url: base_url.into(),
        }
        .render()
        .unwrap();
        assert!(docs.contains("https://links.example.com:8443/api/v1/shorten"));
        assert!(!docs.contains("yue.lat"));
        let index = IndexTemplate {
            base_url: base_url.into(),
            authenticity_token: "test-token".into(),
            altcha_challenge: "test-challenge".into(),
        }
        .render()
        .unwrap();
        assert!(index.contains("https://links.example.com:8443/"));
        assert!(index.contains("<h1>qkgo</h1>"));
    }
}
