mod cli;
mod db;
mod manage;
mod security;

use altcha_lib_rs::ChallengeOptions;
use anyhow::Result;
use askama::Template;
use axum::{
    Extension, Form, Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, State, rejection::FormRejection},
    http::{Request, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use base64::Engine;
use base64::prelude::BASE64_STANDARD;
use chrono::Utc;
use clap::Parser;
use http::Method;
use rand::RngExt;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use std::{
    net::{IpAddr, SocketAddr},
    sync::Arc,
};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use url::Url;

const MAX_URL_LENGTH: usize = 2048;
const MAX_SHORT_CODE_LENGTH: usize = 20;
// Keep only one glyph from each common lookalike pair.
const SHORT_CODE_ALPHABET: &[u8] = b"23456789ACDEFHJKMNPRTVWXY";
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

#[derive(Template)]
#[template(path = "api_docs.html")]
struct ApiDocsTemplate {
    base_url: String,
}

#[derive(Template)]
#[template(path = "about.html")]
struct AboutTemplate {}

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    base_url: String,
    security: FormSecurity,
}

#[derive(Template)]
#[template(path = "password.html")]
struct PasswordTemplate {
    short_code: String,
    security: FormSecurity,
    wrong_password: bool,
}

#[derive(Template)]
#[template(path = "success.html")]
struct SuccessTemplate {
    short_url: String,
    edit_token: String,
}

#[derive(Template)]
#[template(path = "error.html")]
struct ErrorTemplate {
    error_message: String,
}

#[derive(Template)]
#[template(path = "revoked.html")]
struct RevokedTemplate {}

#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    base_url: String,
    altcha_secret: String,
    security: Arc<Security>,
}

struct Security {
    password_attempts: security::RateLimit<String>,
    edit_attempts: security::RateLimit<Option<IpAddr>>,
    password_work: security::PasswordWork,
    api_auth_attempts: security::RateLimit<Option<IpAddr>>,
    api_requests: security::RateLimit<i64>,
}

impl Default for Security {
    fn default() -> Self {
        Self {
            password_attempts: security::RateLimit::new(120, 10),
            edit_attempts: security::RateLimit::new(300, 30),
            password_work: security::PasswordWork::default(),
            api_auth_attempts: security::RateLimit::new(2_400, 600),
            api_requests: security::RateLimit::new(2_400, 120),
        }
    }
}

struct HtmlError {
    status: StatusCode,
    message: String,
}

impl From<(StatusCode, ErrorResponse)> for HtmlError {
    fn from((status, response): (StatusCode, ErrorResponse)) -> Self {
        Self {
            status,
            message: response.error,
        }
    }
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

#[derive(Clone, Copy)]
struct ApiKeyId(i64);

fn invalid_api_key() -> (StatusCode, ErrorResponse) {
    api_error(StatusCode::UNAUTHORIZED, "Missing or invalid API key")
}

fn json_error((status, error): (StatusCode, ErrorResponse)) -> (StatusCode, Json<ErrorResponse>) {
    (status, Json(error))
}

async fn validate_api_key(
    State(state): State<AppState>,
    mut req: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, Json<ErrorResponse>)> {
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip());
    state
        .security
        .api_auth_attempts
        .check(peer)
        .map_err(json_error)?;
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

    let api_key = api_key.ok_or_else(|| json_error(invalid_api_key()))?;
    let id = db::active_key_id(&state.db, api_key)
        .await
        .map_err(|error| {
            tracing::error!("API key lookup failed: {error}");
            json_error(api_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Authentication unavailable",
            ))
        })?
        .ok_or_else(|| json_error(invalid_api_key()))?;
    state.security.api_requests.check(id).map_err(json_error)?;
    req.extensions_mut().insert(ApiKeyId(id));
    Ok(next.run(req).await)
}

fn service_config() -> Result<(SocketAddr, String, String)> {
    let ip: IpAddr = dotenvy::var("LISTEN_ADDR")
        .unwrap_or_else(|_| "127.0.0.1".into())
        .parse()
        .map_err(|_| anyhow::anyhow!("LISTEN_ADDR must be an IPv4 or IPv6 address"))?;
    let port = dotenvy::var("PORT")
        .unwrap_or_else(|_| "3000".into())
        .parse::<u16>()?;
    let base_url =
        normalize_base_url(&dotenvy::var("BASE_URL").unwrap_or_else(|_| "https://qkgo.de".into()))?;
    let secret =
        dotenvy::var("ALTCHA_SECRET").map_err(|_| anyhow::anyhow!("ALTCHA_SECRET must be set"))?;
    anyhow::ensure!(!secret.trim().is_empty(), "ALTCHA_SECRET must not be empty");
    // Do not silently retain environment keys that cannot be revoked using the CLI.
    anyhow::ensure!(
        dotenvy::var("API_KEYS")
            .unwrap_or_default()
            .trim()
            .is_empty(),
        "API_KEYS is no longer supported. Remove it and create keys with quickgo api-key create"
    );
    Ok((SocketAddr::new(ip, port), base_url, secret))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    match dotenvy::dotenv() {
        Ok(_) => {}
        Err(dotenvy::Error::Io(error)) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }

    let cli = cli::Cli::parse();
    if !matches!(cli.command, cli::Command::Serve) {
        return cli::run_local(&cli).await;
    }
    let (listen_addr, base_url, altcha_secret) = service_config()?;
    let db = setup_database(&cli.database_path).await?;

    let app_state = AppState {
        db,
        base_url,
        altcha_secret,
        security: Default::default(),
    };

    let app = build_router(app_state);

    let listener = tokio::net::TcpListener::bind(listen_addr).await?;

    tracing::info!("QuickGo listening on http://{}", listener.local_addr()?);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn build_router(app_state: AppState) -> Router {
    let static_service = ServeDir::new("static").append_index_html_on_directories(false);

    let public_routes = Router::new()
        .route("/", get(root).post(create_url_form))
        .route("/api/v1", get(api_docs))
        .route("/about", get(about))
        .route("/edit", get(manage::edit_form).post(manage::submit_edit))
        .route("/favicon.ico", get(favicon))
        .route(
            "/{short_code}",
            get(redirect_url).post(verify_link_password),
        )
        .nest_service("/static", static_service);

    let api_routes = Router::new()
        .route("/api/v1/shorten", post(create_url))
        .route(
            "/api/v1/links/{code}",
            get(manage::get_link).patch(manage::patch_link),
        )
        .route_layer(middleware::from_fn_with_state(
            app_state.clone(),
            validate_api_key,
        ));

    Router::new()
        .merge(public_routes)
        .merge(api_routes)
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(MAX_REQUEST_SIZE))
                .layer(CorsLayer::new().allow_headers(Any).allow_methods([
                    Method::GET,
                    Method::POST,
                    Method::PATCH,
                ]))
                .layer(CsrfLayer::new(CsrfConfig::default())),
        )
        .with_state(app_state)
        .layer(middleware::from_fn(no_store))
}

async fn no_store(req: Request<Body>, next: Next) -> Response {
    let dynamic = !req.uri().path().starts_with("/static/") && req.uri().path() != "/favicon.ico";
    let mut response = next.run(req).await;
    if dynamic {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            header::HeaderValue::from_static("no-store"),
        );
    }
    response
}

async fn setup_database(path: &str) -> Result<SqlitePool> {
    db::setup(path).await
}

// Keep static pages and API namespaces out of the short-code namespace.
const RESERVED_PATHS: &[&str] = &[
    "about",
    "api",
    "static",
    "favicon.ico",
    "robots.txt",
    "health",
    "healthz",
    "ready",
    "readyz",
    "admin",
    "edit",
    "revoke",
    "login",
    "logout",
    "assets",
    "contact",
    "privacy",
    "terms",
];

fn is_reserved(code: &str) -> bool {
    RESERVED_PATHS
        .iter()
        .any(|path| code.eq_ignore_ascii_case(path))
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
    let template = IndexTemplate {
        base_url: app_state.base_url.clone(),
        security: FormSecurity::new(&app_state, &token)?,
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

async fn about() -> Result<Html<String>, HtmlError> {
    render_html(AboutTemplate {})
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
    Extension(key): Extension<ApiKeyId>,
    Json(payload): Json<CreateUrlRequest>,
) -> Result<(StatusCode, Json<UrlResponse>), (StatusCode, Json<ErrorResponse>)> {
    let result = create_link(&app_state, payload, None, Some(key)).await;
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
    let challenge = check_form(
        &app_state,
        &token,
        &payload.authenticity_token,
        &payload.altcha,
    )?;
    let result = create_link(
        &app_state,
        CreateUrlRequest {
            url: payload.url,
            expires_at: parse_form_expiration(&payload.expires_at).map_err(HtmlError::from)?,
            max_visits: parse_form_max_visits(&payload.max_visits)?,
            password: (!payload.password.is_empty()).then_some(payload.password),
        },
        Some(challenge),
        None,
    )
    .await;
    match result {
        Ok(response) => {
            tracing::info!("Created short URL via form: {}", response.short_code);
            let success_template = SuccessTemplate {
                short_url: response.short_url,
                edit_token: response.edit_token,
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

#[cfg(test)]
async fn shorten_url(
    app_state: AppState,
    url: String,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    shorten_url_with_challenge(app_state, url, None).await
}

#[cfg(test)]
async fn shorten_url_with_challenge(
    app_state: AppState,
    url: String,
    challenge: Option<VerifiedChallenge>,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    create_link(
        &app_state,
        CreateUrlRequest {
            url,
            ..Default::default()
        },
        challenge,
        None,
    )
    .await
}

fn parse_form_expiration(input: &str) -> Result<Option<i64>, (StatusCode, ErrorResponse)> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if let Ok(date) = chrono::DateTime::parse_from_rfc3339(input) {
        return Ok(Some(date.timestamp()));
    }
    // The native picker submits UTC without a suffix when the conversion script is unavailable.
    for format in ["%Y-%m-%dT%H:%M", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(date) = chrono::NaiveDateTime::parse_from_str(input, format) {
            return Ok(Some(date.and_utc().timestamp()));
        }
    }
    Err(api_error(
        StatusCode::BAD_REQUEST,
        "Choose a valid expiration date and time.",
    ))
}

fn validate_expiration(expires_at: Option<i64>) -> Result<(), (StatusCode, ErrorResponse)> {
    // Limit to four-digit years so API dates round-trip through the HTML form.
    const RFC3339_SECONDS: std::ops::RangeInclusive<i64> = -62_167_219_200..=253_402_300_799;
    if expires_at.is_some_and(|value| !RFC3339_SECONDS.contains(&value)) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Expiration is outside the supported range",
        ));
    }
    Ok(())
}

fn parse_form_max_visits(input: &str) -> Result<Option<i64>, (StatusCode, ErrorResponse)> {
    if input.trim().is_empty() {
        return Ok(None);
    }
    input.trim().parse().map(Some).map_err(|_| {
        api_error(
            StatusCode::BAD_REQUEST,
            "Maximum uses must be a positive integer",
        )
    })
}

fn validate_max_visits(max_visits: Option<i64>) -> Result<(), (StatusCode, ErrorResponse)> {
    if max_visits.is_some_and(|max| max <= 0) {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Maximum uses must be a positive integer",
        ));
    }
    Ok(())
}

async fn create_link(
    app_state: &AppState,
    mut payload: CreateUrlRequest,
    mut challenge: Option<VerifiedChallenge>,
    owner: Option<ApiKeyId>,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    payload.url = normalize_destination(&payload.url, &app_state.base_url)?;
    validate_expiration(payload.expires_at)?;
    validate_max_visits(payload.max_visits)?;
    let password_hash = match payload.password.take() {
        Some(password) => {
            if let Some(proof) = challenge.take() {
                record_challenge(&app_state.db, proof).await?;
            }
            Some(app_state.security.password_work.hash(password).await?)
        }
        None => None,
    };
    store_url(
        app_state,
        payload,
        generate_short_code,
        challenge,
        password_hash,
        owner,
    )
    .await
}

fn normalize_destination(url: &str, base_url: &str) -> Result<String, (StatusCode, ErrorResponse)> {
    if let Err(error) = validate_url_length(url) {
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
    let parsed = Url::parse(&url).map_err(|_| api_error(StatusCode::BAD_REQUEST, "Invalid URL"))?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "URL credentials are not allowed",
        ));
    }
    let base = Url::parse(base_url).expect("validated base URL");
    if parsed.host_str().map(|host| host.trim_end_matches('.'))
        == base.host_str().map(|host| host.trim_end_matches('.'))
    {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "Links to this shortener are not allowed",
        ));
    }
    let normalized = parsed.to_string();
    validate_url_length(&normalized)
        .map_err(|error| (StatusCode::BAD_REQUEST, ErrorResponse { error }))?;
    Ok(normalized)
}

#[cfg(test)]
async fn store_url_with_generator(
    app_state: &AppState,
    url: String,
    mut generate: impl FnMut() -> String,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    store_url(
        app_state,
        CreateUrlRequest {
            url,
            ..Default::default()
        },
        &mut generate,
        None,
        None,
        None,
    )
    .await
}

fn api_error(status: StatusCode, message: &str) -> (StatusCode, ErrorResponse) {
    (
        status,
        ErrorResponse {
            error: message.into(),
        },
    )
}

fn database_error(error: sqlx::Error) -> (StatusCode, ErrorResponse) {
    tracing::error!("Database operation failed: {}", error);
    api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Database operation failed. Please try again.",
    )
}

async fn store_url(
    app_state: &AppState,
    payload: CreateUrlRequest,
    mut generate: impl FnMut() -> String,
    challenge: Option<VerifiedChallenge>,
    password_hash: Option<String>,
    owner: Option<ApiKeyId>,
) -> Result<UrlResponse, (StatusCode, ErrorResponse)> {
    let owner_id = owner.map(|key| key.0);
    let mut tx = app_state.db.begin().await.map_err(database_error)?;
    if let Some(challenge) = challenge {
        consume_challenge(&mut tx, challenge).await?;
    }
    for _ in 0..10 {
        let short_code = generate();
        if is_reserved(&short_code) {
            continue;
        }
        let edit_token = db::generate_secret("qke_").map_err(|error| {
            tracing::error!("Edit token generation failed: {error}");
            api_error(StatusCode::INTERNAL_SERVER_ERROR, "Unable to create link")
        })?;
        match sqlx::query(
            "INSERT INTO urls (short_code, original_url, edit_token_hash, expires_at, max_visits, password_hash, updated_at, created_by_api_key_id)
             SELECT ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, ?
             WHERE ? IS NULL OR EXISTS (SELECT 1 FROM api_keys WHERE id = ? AND revoked_at IS NULL)",
        )
        .bind(&short_code)
        .bind(&payload.url)
        .bind(db::hash_key(&edit_token))
        .bind(payload.expires_at)
        .bind(payload.max_visits)
        .bind(&password_hash)
        .bind(owner_id)
        .bind(owner_id)
        .bind(owner_id)
        .execute(&mut *tx)
        .await
        {
            Ok(result) if result.rows_affected() == 1 => {
                tx.commit().await.map_err(database_error)?;
                return Ok(UrlResponse {
                    original_url: payload.url,
                    short_url: format!("{}/{}", app_state.base_url, short_code),
                    short_code,
                    edit_token,
                });
            }
            Ok(_) => return Err(invalid_api_key()),
            Err(sqlx::Error::Database(error)) if error.is_unique_violation() => continue,
            Err(error) => return Err(database_error(error)),
        }
    }
    Err(api_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Unable to generate unique short code. Please try again.",
    ))
}

async fn consume_challenge(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    challenge: VerifiedChallenge,
) -> Result<(), (StatusCode, ErrorResponse)> {
    let now = Utc::now().timestamp();
    if challenge.expires_at <= now {
        return Err(api_error(
            StatusCode::BAD_REQUEST,
            "CAPTCHA expired. Please refresh the page.",
        ));
    }
    // The first statement is a write, so concurrent SQLite transactions serialize here.
    sqlx::query("DELETE FROM used_challenges WHERE expires_at <= ?")
        .bind(now)
        .execute(&mut **tx)
        .await
        .map_err(database_error)?;
    let result = sqlx::query(
        "INSERT INTO used_challenges (challenge_id, expires_at) SELECT ?, ? WHERE ? > unixepoch()",
    )
    .bind(&challenge.id)
    .bind(challenge.expires_at)
    .bind(challenge.expires_at)
    .execute(&mut **tx)
    .await;
    match result {
        Ok(result) if result.rows_affected() == 1 => {}
        Ok(_) => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "CAPTCHA expired. Please refresh the page.",
            ));
        }
        Err(sqlx::Error::Database(error)) if error.is_unique_violation() => {
            return Err(api_error(
                StatusCode::BAD_REQUEST,
                "CAPTCHA already used. Please refresh the page.",
            ));
        }
        Err(error) => return Err(database_error(error)),
    }
    Ok(())
}

async fn verify_sensitive_form(
    app: &AppState,
    token: &CsrfToken,
    authenticity_token: &str,
    altcha: &str,
) -> Result<(), HtmlError> {
    let challenge = check_form(app, token, authenticity_token, altcha)?;
    record_challenge(&app.db, challenge).await?;
    Ok(())
}

async fn record_challenge(
    db: &SqlitePool,
    challenge: VerifiedChallenge,
) -> Result<(), (StatusCode, ErrorResponse)> {
    let mut tx = db.begin().await.map_err(database_error)?;
    consume_challenge(&mut tx, challenge).await?;
    tx.commit().await.map_err(database_error)?;
    Ok(())
}

async fn redirect_url(
    token: CsrfToken,
    method: Method,
    Path(short_code): Path<String>,
    State(app_state): State<AppState>,
) -> Result<Response, HtmlError> {
    validate_redirect_code(&short_code)?;
    for _ in 0..3 {
        let link = redirect_target(&app_state.db, &short_code).await?;
        if let Some(response) = link.unavailable()? {
            return Ok(response);
        }
        if link.password_hash.is_some() {
            return password_page(&app_state, token, short_code, false);
        }
        let response = link.redirect(StatusCode::FOUND)?;
        if method == Method::HEAD
            || link.max_visits.is_none()
            || link.consume_visit(&app_state.db, &short_code).await?
        {
            return Ok(response);
        }
    }
    Err(link_unavailable())
}

#[derive(Deserialize)]
struct PasswordForm {
    password: String,
    #[serde(default)]
    authenticity_token: String,
    #[serde(default)]
    altcha: String,
}

async fn verify_link_password(
    token: CsrfToken,
    Path(short_code): Path<String>,
    State(app): State<AppState>,
    form: Result<Form<PasswordForm>, FormRejection>,
) -> Result<Response, HtmlError> {
    validate_redirect_code(&short_code)?;
    let target = redirect_target(&app.db, &short_code).await?;
    if let Some(response) = target.unavailable()? {
        return Ok(response);
    }
    let Some(password_hash) = target.password_hash else {
        return Err(link_unavailable());
    };
    let Form(form) = match form {
        Ok(form) => form,
        Err(rejection) => return Ok(rejection.into_response()),
    };
    verify_sensitive_form(&app, &token, &form.authenticity_token, &form.altcha).await?;
    app.security.password_attempts.check(short_code.clone())?;
    if !app
        .security
        .password_work
        .verify(form.password, password_hash.clone())
        .await?
    {
        return password_page(&app, token, short_code, true);
    }

    for _ in 0..3 {
        let target = redirect_target(&app.db, &short_code).await?;
        if let Some(response) = target.unavailable()? {
            return Ok(response);
        }
        if target.password_hash.as_deref() != Some(&password_hash) {
            return Err(link_unavailable());
        }
        let response = target.redirect(StatusCode::SEE_OTHER)?;
        if target.max_visits.is_none() || target.consume_visit(&app.db, &short_code).await? {
            return Ok(response);
        }
    }
    Err(link_unavailable())
}

fn link_unavailable() -> HtmlError {
    HtmlError {
        status: StatusCode::NOT_FOUND,
        message: "This link is unavailable.".into(),
    }
}

fn password_page(
    app: &AppState,
    token: CsrfToken,
    short_code: String,
    wrong_password: bool,
) -> Result<Response, HtmlError> {
    let template = PasswordTemplate {
        short_code,
        security: FormSecurity::new(app, &token)?,
        wrong_password,
    };
    let status = if wrong_password {
        StatusCode::UNAUTHORIZED
    } else {
        StatusCode::OK
    };
    Ok((status, token, render_html(template)?).into_response())
}

fn render_html(template: impl Template) -> Result<Html<String>, HtmlError> {
    template.render().map(Html).map_err(|error| {
        tracing::error!("Template rendering error: {error}");
        HtmlError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Unable to load page".into(),
        }
    })
}

fn validate_redirect_code(short_code: &str) -> Result<(), HtmlError> {
    if is_reserved(short_code)
        || short_code.is_empty()
        || short_code.len() > MAX_SHORT_CODE_LENGTH
        || !short_code.bytes().all(|c| c.is_ascii_alphanumeric())
    {
        return Err(link_unavailable());
    }
    Ok(())
}

#[derive(sqlx::FromRow)]
struct RedirectTarget {
    original_url: String,
    revoked_at: Option<String>,
    expires_at: Option<i64>,
    max_visits: Option<i64>,
    visit_count: i64,
    password_hash: Option<String>,
    paused: bool,
}

async fn redirect_target(db: &SqlitePool, short_code: &str) -> Result<RedirectTarget, HtmlError> {
    sqlx::query_as(
        "SELECT original_url, revoked_at, expires_at, max_visits, visit_count, password_hash, paused
         FROM urls WHERE short_code = ?",
    )
    .bind(short_code)
    .fetch_optional(db)
    .await
    .map_err(database_error)?
    .ok_or_else(link_unavailable)
}

impl RedirectTarget {
    fn unavailable(&self) -> Result<Option<Response>, HtmlError> {
        if self.revoked_at.is_some() {
            let html = RevokedTemplate {}.render().map_err(|_| HtmlError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "Unable to load page".into(),
            })?;
            return Ok(Some((StatusCode::GONE, Html(html)).into_response()));
        }
        if self.paused
            || self
                .expires_at
                .is_some_and(|expiry| expiry <= Utc::now().timestamp())
            || self.max_visits.is_some_and(|max| self.visit_count >= max)
        {
            return Err(link_unavailable());
        }
        Ok(None)
    }

    fn redirect(&self, status: StatusCode) -> Result<Response, HtmlError> {
        let location =
            header::HeaderValue::from_str(&self.original_url).map_err(|_| HtmlError {
                status: StatusCode::INTERNAL_SERVER_ERROR,
                message: "This link has an invalid destination.".into(),
            })?;
        Ok((status, [(header::LOCATION, location)], ()).into_response())
    }

    async fn consume_visit(&self, db: &SqlitePool, code: &str) -> Result<bool, HtmlError> {
        // Count only redirects for the destination we are about to send.
        let result = sqlx::query(
            "UPDATE urls SET visit_count = visit_count + 1
             WHERE short_code = ? AND original_url = ? AND password_hash IS ? AND revoked_at IS NULL AND paused = 0
               AND (expires_at IS NULL OR expires_at > unixepoch())
               AND max_visits IS NOT NULL AND visit_count < max_visits",
        )
        .bind(code)
        .bind(&self.original_url)
        .bind(&self.password_hash)
        .execute(db)
        .await
        .map_err(database_error)?;
        Ok(result.rows_affected() == 1)
    }
}

fn generate_short_code() -> String {
    const CODE_LENGTH: usize = 6;

    let mut rng = rand::rng();
    (0..CODE_LENGTH)
        .map(|_| {
            let idx = rng.random_range(0..SHORT_CODE_ALPHABET.len());
            SHORT_CODE_ALPHABET[idx] as char
        })
        .collect()
}

struct FormSecurity {
    authenticity_token: String,
    altcha_challenge: String,
}

impl FormSecurity {
    fn new(app: &AppState, token: &CsrfToken) -> Result<Self, HtmlError> {
        let failure = || HtmlError {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: "Failed to generate security challenge. Please try again.".into(),
        };
        let challenge = altcha_lib_rs::create_challenge(ChallengeOptions {
            hmac_key: &app.altcha_secret,
            max_number: Some(100_000),
            expires: Some(Utc::now() + chrono::TimeDelta::minutes(5)),
            ..Default::default()
        })
        .map_err(|_| failure())?;
        let challenge = serde_json::to_vec(&challenge).map_err(|_| failure())?;
        Ok(Self {
            authenticity_token: token.authenticity_token().map_err(|_| failure())?,
            altcha_challenge: BASE64_STANDARD.encode(challenge),
        })
    }
}

fn check_form(
    app: &AppState,
    token: &CsrfToken,
    authenticity_token: &str,
    altcha: &str,
) -> Result<VerifiedChallenge, HtmlError> {
    token.verify(authenticity_token).map_err(|_| HtmlError {
        status: StatusCode::FORBIDDEN,
        message: "Invalid security token. Please refresh the page and try again.".into(),
    })?;
    verify_altcha(&app.altcha_secret, altcha).map_err(|message| HtmlError {
        status: StatusCode::BAD_REQUEST,
        message,
    })
}

#[derive(Debug)]
struct VerifiedChallenge {
    id: String,
    expires_at: i64,
}

#[derive(Deserialize)]
struct AltchaResponse {
    algorithm: altcha_lib_rs::algorithm::AltchaAlgorithm,
    challenge: String,
    number: u64,
    salt: String,
    signature: String,
}

fn verify_altcha(secret: &str, payload: &str) -> Result<VerifiedChallenge, String> {
    let failure = || "CAPTCHA verification failed. Please refresh the page.".to_string();
    if payload.is_empty() || payload.len() > 8192 {
        return Err(failure());
    }
    let decoded = BASE64_STANDARD.decode(payload).map_err(|_| failure())?;
    let response: AltchaResponse = serde_json::from_slice(&decoded).map_err(|_| failure())?;
    // The widget reports elapsed time as a decimal. It is client metadata, not part of the proof.
    let solution = altcha_lib_rs::Payload {
        algorithm: response.algorithm,
        challenge: response.challenge,
        number: response.number,
        salt: response.salt,
        signature: response.signature,
        took: None,
    };
    altcha_lib_rs::verify_solution(&solution, secret, true).map_err(|_| failure())?;
    // Expiration must be present: the library permits payloads without it.
    let query = solution.salt.split_once('?').ok_or_else(failure)?.1;
    let expires: Vec<_> = url::form_urlencoded::parse(query.as_bytes())
        .filter(|(name, _)| name == "expires")
        .collect();
    if expires.len() != 1 {
        return Err(failure());
    }
    let expires_at = expires[0].1.parse::<i64>().map_err(|_| failure())?;
    if expires_at <= Utc::now().timestamp() {
        return Err(failure());
    }
    // Identify the verified challenge, not raw JSON/base64 or mutable client metadata.
    Ok(VerifiedChallenge {
        id: solution.challenge,
        expires_at,
    })
}

#[derive(Default, Deserialize)]
struct CreateUrlRequest {
    url: String,
    expires_at: Option<i64>,
    max_visits: Option<i64>,
    password: Option<String>,
}

#[derive(Deserialize)]
struct CreateUrlFormRequest {
    url: String,
    #[serde(default)]
    expires_at: String,
    #[serde(default)]
    max_visits: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    authenticity_token: String,
    #[serde(default)]
    altcha: String,
}

#[derive(Serialize)]
struct UrlResponse {
    original_url: String,
    short_code: String,
    short_url: String,
    edit_token: String,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    error: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::Row;

    async fn state() -> AppState {
        AppState {
            db: setup_database(":memory:").await.unwrap(),
            base_url: "https://qkgo.de".into(),
            altcha_secret: "test-secret".into(),
            security: Default::default(),
        }
    }

    #[test]
    fn expiration_forms_accept_picker_values_and_preserve_utc_seconds() {
        let expected = chrono::DateTime::parse_from_rfc3339("2030-06-15T12:00:00Z")
            .unwrap()
            .timestamp();
        for input in [
            "2030-06-15T12:00",
            "2030-06-15T12:00:00",
            "2030-06-15T20:00:00+08:00",
        ] {
            assert_eq!(parse_form_expiration(input).unwrap(), Some(expected));
        }
        assert_eq!(parse_form_expiration("").unwrap(), None);
        assert!(parse_form_expiration("2030-02-30T12:00").is_err());
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
        let redirect = super::management_tests::request(build_router(state), "/abcd").await;
        let response = redirect;
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
        assert_eq!(attempts, 0);
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
                .all(|c| SHORT_CODE_ALPHABET.contains(&c))
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
            security: FormSecurity {
                authenticity_token: "test-token".into(),
                altcha_challenge: "test-challenge".into(),
            },
        }
        .render()
        .unwrap();
        assert!(index.contains("https://links.example.com:8443/"));
        assert!(index.contains("<h1>QuickGo</h1>"));
    }
}

#[cfg(test)]
mod management_tests;
