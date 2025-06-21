use askama::Template;
use axum::{
    Form, Json, Router,
    extract::{Path, State},
    http::{StatusCode, header},
    response::{Html, Redirect, Response},
    routing::{get, post},
};
use dotenv::dotenv;
use rand::Rng;
use serde::{Deserialize, Serialize};
use sqlx::{Row, SqlitePool};
use std::env;
use tracing_subscriber;

// Template structs
#[derive(Template)]
#[template(path = "index.html")]
struct IndexTemplate;

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

// Shared state with SQLite connection pool
#[derive(Clone)]
struct AppState {
    db: SqlitePool,
    base_url: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenv().ok();

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a valid number");

    let base_url = env::var("BASE_URL").unwrap_or_else(|_| "https://yue.lat".to_string());

    // Remove trailing slash if present
    let base_url = base_url.trim_end_matches('/').to_string();

    tracing::info!("Using base URL: {}", base_url);

    // Initialize SQLite connection pool
    let db = setup_database().await.expect("Failed to setup database");

    let app_state = AppState { db, base_url };

    let app = Router::new()
        .route("/", get(root).post(create_url_form))
        .route("/shorten", post(create_url))
        .route("/favicon.ico", get(favicon))
        .route("/{short_code}", get(redirect_url))
        .with_state(app_state);

    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
        .await
        .unwrap();

    tracing::info!("URL Shortener listening on http://0.0.0.0:{}", port);
    axum::serve(listener, app).await.unwrap();
}

async fn setup_database() -> Result<SqlitePool, sqlx::Error> {
    // Create connection pool with configuration
    let pool = SqlitePool::connect_with(
        sqlx::sqlite::SqliteConnectOptions::new()
            .filename("urls.db")
            .create_if_missing(true)
            .pragma("journal_mode", "WAL") // Enable WAL mode for better concurrency
            .pragma("synchronous", "NORMAL")
            .pragma("cache_size", "1000")
            .pragma("foreign_keys", "true")
            .pragma("temp_store", "memory"),
    )
    .await?;

    // Create table if it doesn't exist
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS urls (
            short_code TEXT PRIMARY KEY,
            original_url TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
    )
    .execute(&pool)
    .await?;

    tracing::info!("Database pool initialized with {} connections", pool.size());
    Ok(pool)
}

async fn favicon() -> Response {
    // Simple link/chain icon as SVG favicon
    let svg_favicon = r##"<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16" fill="#007bff">
        <path d="M4.5 1A1.5 1.5 0 0 0 3 2.5v3A1.5 1.5 0 0 0 4.5 7h7A1.5 1.5 0 0 0 13 5.5v-3A1.5 1.5 0 0 0 11.5 1h-7z"/>
        <path d="M11.5 9A1.5 1.5 0 0 0 10 10.5v3A1.5 1.5 0 0 0 11.5 15h3A1.5 1.5 0 0 0 16 13.5v-3A1.5 1.5 0 0 0 14.5 9h-3z"/>
        <path d="M8.854 8.146a.5.5 0 0 0-.708.708l1.5 1.5a.5.5 0 0 0 .708-.708l-1.5-1.5z"/>
    </svg>"##;

    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "image/svg+xml")
        .header(header::CACHE_CONTROL, "public, max-age=604800") // Cache for 1 week
        .body(svg_favicon.into())
        .unwrap()
}

async fn root() -> Result<Html<String>, StatusCode> {
    let template = IndexTemplate;
    match template.render() {
        Ok(html) => Ok(Html(html)),
        Err(e) => {
            tracing::error!("Template rendering error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
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
    State(app_state): State<AppState>,
    Form(payload): Form<CreateUrlRequest>,
) -> Result<Html<String>, StatusCode> {
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
    // Validate URL
    if url.trim().is_empty() {
        return Err(ErrorResponse {
            error: "URL cannot be empty".to_string(),
        });
    }

    let url = url.trim().to_string();

    // Basic URL validation
    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(ErrorResponse {
            error: "URL must start with http:// or https://".to_string(),
        });
    }

    let mut attempts = 0;
    let max_attempts = 10;

    loop {
        let short_code = generate_short_code();

        // Check if short code already exists
        let exists = sqlx::query("SELECT 1 FROM urls WHERE short_code = ?")
            .bind(&short_code)
            .fetch_optional(&app_state.db)
            .await;

        match exists {
            Ok(None) => {
                // Short code doesn't exist, try to insert
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
                // Short code exists, try again
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

// Request/Response types
#[derive(Deserialize)]
struct CreateUrlRequest {
    url: String,
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
