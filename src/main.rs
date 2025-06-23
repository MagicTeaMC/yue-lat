use anyhow::Result;
use askama::Template;
use axum::{
    Form, Json, Router,
    extract::{DefaultBodyLimit, Path, State},
    http::{StatusCode, header},
    response::{Html, Redirect, Response},
    routing::{get, post},
};
use axum_csrf::{CsrfConfig, CsrfLayer, CsrfToken};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use tower::ServiceBuilder;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber;

const MAX_URL_LENGTH: usize = 2048;
const MAX_SHORT_CODE_LENGTH: usize = 20;
const MAX_REQUEST_SIZE: usize = 1024 * 1024;

#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate {
    authenticity_token: String,
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
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    dotenvy::dotenv_override()?;

    let port: u16 = dotenvy::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a valid number");

    let base_url = dotenvy::var("BASE_URL").unwrap_or_else(|_| "https://yue.lat".to_string());

    let base_url = base_url.trim_end_matches('/').to_string();

    tracing::info!("Using base URL: {}", base_url);

    let db = setup_database().await.expect("Failed to setup database");

    let app_state = AppState { db, base_url };

    let app = Router::new()
        .route("/", get(root).post(create_url_form))
        .route("/api/v1/shorten", post(create_url))
        .route("/favicon.ico", get(favicon))
        .route("/{short_code}", get(redirect_url))
        .layer(
            ServiceBuilder::new()
                .layer(DefaultBodyLimit::max(MAX_REQUEST_SIZE))
                .layer(CorsLayer::new().allow_headers(Any).allow_methods(Any))
                .layer(CsrfLayer::new(CsrfConfig::default()))
        )
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port)).await?;

    tracing::info!("URL Shortener listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await?;

    Ok(())
}

async fn setup_database() -> Result<SqlitePool, sqlx::Error> {
    let pool = SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename("urls.db")
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
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err("URL must start with http:// or https://".to_string());
    }

    if url.chars().any(|c| c.is_control() && c != '\t') {
        return Err("URL contains invalid control characters".to_string());
    }

    Ok(())
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

async fn root(token: CsrfToken) -> Result<(CsrfToken, Html<String>), StatusCode> {
    let template = IndexTemplate {
        authenticity_token: token.authenticity_token().unwrap(),
    };

    match template.render() {
        Ok(html) => Ok((token, Html(html))),
        Err(e) => {
            tracing::error!("Template rendering error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn create_url(
    State(app_state): State<AppState>,
    Json(payload): Json<CreateUrlRequest>
) -> Result<(StatusCode, Json<UrlResponse>), (StatusCode, Json<ErrorResponse>)> {
    let result = shorten_url(app_state, payload.url).await;
    match result {
        Ok(response) => {
            tracing::info!(
                "Created short URL: {} -> {}",
                response.short_code,
                response.original_url
            );
            Ok((StatusCode::CREATED, Json(response)))
        }
        Err(error_response) => {
            tracing::warn!("Failed to create short URL: {}", error_response.error);
            Err((StatusCode::BAD_REQUEST, Json(error_response)))
        }
    }
}

async fn create_url_form(
    token: CsrfToken,
    State(app_state): State<AppState>,
    Form(payload): Form<CreateUrlFormRequest>
) -> Result<Html<String>, StatusCode> {

    if token.verify(&payload.authenticity_token).is_err() {
        tracing::warn!("CSRF token verification failed");
        return Err(StatusCode::BAD_REQUEST);
    }

    let result = shorten_url(app_state, payload.url).await;

    match result {
        Ok(response) => {
            tracing::info!(
                "Created short URL via form: {} -> {}",
                response.short_code,
                response.original_url
            );

            let success_template = SuccessTemplate {
                short_url: response.short_url,
            };

            match success_template.render() {
                Ok(html) => Ok(Html(html)),
                Err(e) => {
                    tracing::error!("Template rendering error: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
        Err(error_response) => {
            tracing::warn!(
                "Failed to create short URL via form: {}",
                error_response.error
            );

            let error_template = ErrorTemplate {
                error_message: error_response.error,
            };

            match error_template.render() {
                Ok(html) => Ok(Html(html)),
                Err(e) => {
                    tracing::error!("Template rendering error: {}", e);
                    Err(StatusCode::INTERNAL_SERVER_ERROR)
                }
            }
        }
    }
}

async fn shorten_url(app_state: AppState, url: String) -> Result<UrlResponse, ErrorResponse> {
    if let Err(error) = validate_url_length(&url) {
        return Err(ErrorResponse { error });
    }

    if url.trim().is_empty() {
        return Err(ErrorResponse {
            error: "URL cannot be empty".to_string(),
        });
    }

    let url = url.trim().to_string();

    if let Err(error) = validate_url_format(&url) {
        return Err(ErrorResponse { error });
    }

    let mut attempts = 0;
    let max_attempts = 10;

    loop {
        let short_code = generate_short_code();

        if let Err(error) = validate_short_code_length(&short_code) {
            tracing::error!("Generated short code validation failed: {}", error);
            return Err(ErrorResponse {
                error: "Internal error generating short code".to_string(),
            });
        }

        let exists = sqlx::query("SELECT 1 FROM urls WHERE short_code = ?")
            .bind(&short_code)
            .fetch_optional(&app_state.db)
            .await;

        match exists {
            Ok(None) => {
                let result =
                    sqlx::query("INSERT INTO urls (short_code, original_url) VALUES (?, ?)")
                        .bind(&short_code)
                        .bind(&url)
                        .execute(&app_state.db)
                        .await;

                match result {
                    Ok(_) => {
                        let response = UrlResponse {
                            original_url: url,
                            short_code: short_code.clone(),
                            short_url: format!("{}/{}", app_state.base_url, short_code),
                        };
                        return Ok(response);
                    }
                    Err(e) => {
                        tracing::error!("Database error: {}", e);
                        return Err(ErrorResponse {
                            error: "Database error".to_string(),
                        });
                    }
                }
            }
            Ok(Some(_)) => {
                attempts += 1;
                if attempts >= max_attempts {
                    return Err(ErrorResponse {
                        error: "Unable to generate unique short code".to_string(),
                    });
                }
                continue;
            }
            Err(e) => {
                tracing::error!("Database query error: {}", e);
                return Err(ErrorResponse {
                    error: "Database error".to_string(),
                });
            }
        }
    }
}

async fn redirect_url(
    Path(short_code): Path<String>,
    State(app_state): State<AppState>,
) -> Result<Redirect, StatusCode> {
    if let Err(error) = validate_short_code_length(&short_code) {
        tracing::warn!("Short code validation failed in redirect: {}", error);
        return Err(StatusCode::BAD_REQUEST);
    }

    if !short_code.chars().all(|c| c.is_alphanumeric()) {
        tracing::warn!("Invalid characters in short code: {}", short_code);
        return Err(StatusCode::BAD_REQUEST);
    }

    let result = sqlx::query("SELECT original_url FROM urls WHERE short_code = ?")
        .bind(&short_code)
        .fetch_optional(&app_state.db)
        .await;

    match result {
        Ok(Some(row)) => {
            let original_url: String = row.get("original_url");
            tracing::debug!("Redirecting {} -> {}", short_code, original_url);
            Ok(Redirect::permanent(&original_url))
        }
        Ok(None) => {
            tracing::warn!("Short code not found: {}", short_code);
            Err(StatusCode::NOT_FOUND)
        }
        Err(e) => {
            tracing::error!("Database error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

fn generate_short_code() -> String {
    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    const CODE_LENGTH: usize = 4;

    let mut rng = rand::rng();
    (0..CODE_LENGTH)
        .map(|_| {
            let idx = rng.random_range(0..CHARSET.len());
            CHARSET[idx] as char
        })
        .collect()
}

#[derive(Deserialize)]
struct CreateUrlRequest {
    url: String,
}

#[derive(Deserialize)]
struct CreateUrlFormRequest {
    url: String,
    authenticity_token: String,
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
