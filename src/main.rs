use axum::{
    Form, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, Redirect},
    routing::{get, post},
};
use dotenv::dotenv;
use rand::Rng;
use rusqlite::{Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use std::{env, sync::Arc};
use tokio::sync::Mutex;
use tracing_subscriber;

// Shared state for SQLite connection
type DbState = Arc<Mutex<Connection>>;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    dotenv().ok();

    let port: u16 = env::var("PORT")
        .unwrap_or_else(|_| "3000".to_string())
        .parse()
        .expect("PORT must be a valid number");

    // Initialize SQLite database
    let db = setup_database().await.expect("Failed to setup database");
    let db_state: DbState = Arc::new(Mutex::new(db));

    let app = Router::new()
        .route("/", get(root).post(create_url_form))
        .route("/shorten", post(create_url))
        .route("/{short_code}", get(redirect_url))
        .with_state(db_state);

    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .unwrap();

    tracing::info!("URL Shortener listening on http://127.0.0.1:{}", port);
    axum::serve(listener, app).await.unwrap();
}

async fn setup_database() -> SqliteResult<Connection> {
    let conn = Connection::open("urls.db")?;

    conn.execute(
        "CREATE TABLE IF NOT EXISTS urls (
            short_code TEXT PRIMARY KEY,
            original_url TEXT NOT NULL,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )",
        [],
    )?;

    tracing::info!("Database initialized");
    Ok(conn)
}

fn get_common_styles() -> &'static str {
    r#"
        body { font-family: system-ui, sans-serif; max-width: 500px; margin: 2rem auto; padding: 1rem; background: #1a1a1a; color: #e0e0e0; }
        input { width: 100%; padding: 0.5rem; margin: 0.5rem 0; border: 1px solid #404040; border-radius: 4px; box-sizing: border-box; background: #2a2a2a; color: #e0e0e0; }
        input:focus { outline: none; border-color: #007bff; }
        button { background: #007bff; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { margin-top: 1rem; padding: 1rem; background: #2a2a2a; border-radius: 4px; word-break: break-all; border: 1px solid #404040; }
        .footer { margin-top: 2rem; text-align: center; padding-top: 1rem; border-top: 1px solid #404040; }
        .social-links { display: flex; justify-content: center; gap: 1rem; margin-top: 0.5rem; }
        .social-links a { color: #007bff; text-decoration: none; padding: 0.5rem; border-radius: 4px; transition: background-color 0.2s; }
        .social-links a:hover { background-color: #2a2a2a; }
        .social-links a::before { margin-right: 0.5rem; }
        .github::before { content: "🐙"; }
        .discord::before { content: "💬"; }
        a { color: #4da6ff; text-decoration: none; }
        a:hover { text-decoration: underline; }
        .error { background: #3a1f1f; color: #ff6b6b; padding: 1rem; border-radius: 4px; border: 1px solid #5a2a2a; }
    "#
}

fn get_footer_html() -> &'static str {
    r#"
    <div class="footer">
        <div>Made with ❤️ in Taiwan</div>
        <div class="social-links">
            <a href="https://github.com/MagicTeaMC/yue-lat" class="github" target="_blank">GitHub</a>
            <a href="https://discord.gg/uQ4UXANnP2" class="discord" target="_blank">Discord</a>
        </div>
    </div>
    "#
}

async fn root() -> Html<&'static str> {
    Html(
        r#"
<!DOCTYPE html>
<html>
<head>
    <title>URL Shortener</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        body { font-family: system-ui, sans-serif; max-width: 500px; margin: 2rem auto; padding: 1rem; background: #1a1a1a; color: #e0e0e0; }
        input { width: 100%; padding: 0.5rem; margin: 0.5rem 0; border: 1px solid #404040; border-radius: 4px; box-sizing: border-box; background: #2a2a2a; color: #e0e0e0; }
        input:focus { outline: none; border-color: #007bff; }
        button { background: #007bff; color: white; padding: 0.5rem 1rem; border: none; border-radius: 4px; cursor: pointer; }
        button:hover { background: #0056b3; }
        .result { margin-top: 1rem; padding: 1rem; background: #2a2a2a; border-radius: 4px; word-break: break-all; border: 1px solid #404040; }
        .footer { margin-top: 2rem; text-align: center; padding-top: 1rem; border-top: 1px solid #404040; }
        .social-links { display: flex; justify-content: center; gap: 1rem; margin-top: 0.5rem; }
        .social-links a { color: #007bff; text-decoration: none; padding: 0.5rem; border-radius: 4px; transition: background-color 0.2s; }
        .social-links a:hover { background-color: #2a2a2a; }
        .social-links a::before { margin-right: 0.5rem; }
        .github::before { content: "🐙"; }
        .discord::before { content: "💬"; }
    </style>
</head>
<body>
    <h1>URL Shortener</h1>
    <form method="post">
        <input type="url" name="url" placeholder="https://example.com" required>
        <button type="submit">Shorten</button>
    </form>
    
    <div class="footer">
        <div>Made with ❤️ in Taiwan</div>
        <div class="social-links">
            <a href="https://github.com/MagicTeaMC/yue-lat" class="github" target="_blank">GitHub</a>
            <a href="https://discord.gg/uQ4UXANnP2" class="discord" target="_blank">Discord</a>
        </div>
    </div>
</body>
</html>
    "#,
    )
}

async fn create_url(
    State(db): State<DbState>,
    Json(payload): Json<CreateUrlRequest>,
) -> Result<(StatusCode, Json<UrlResponse>), (StatusCode, Json<ErrorResponse>)> {
    let result = shorten_url(db, payload.url).await;
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
    State(db): State<DbState>,
    Form(payload): Form<CreateUrlRequest>,
) -> Html<String> {
    let result = shorten_url(db, payload.url).await;
    match result {
        Ok(response) => {
            tracing::info!(
                "Created short URL via form: {} -> {}",
                response.short_code,
                response.original_url
            );
            Html(format!(
                r#"
<!DOCTYPE html>
<html>
<head>
    <title>URL Shortened</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        {}
    </style>
</head>
<body>
    <h1>URL Shortened</h1>
    <div class="result">
        <p><strong>Short URL:</strong> <a href="{}" target="_blank">{}</a></p>
    </div>
    <a href="/">← Create Another</a>
    
    {}
</body>
</html>
            "#,
                get_common_styles(),
                response.short_url,
                response.short_url,
                get_footer_html()
            ))
        }
        Err(error_response) => {
            tracing::warn!(
                "Failed to create short URL via form: {}",
                error_response.error
            );
            Html(format!(
                r#"
<!DOCTYPE html>
<html>
<head>
    <title>Error</title>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>
        {}
    </style>
</head>
<body>
    <h1>Error</h1>
    <div class="error">{}</div>
    <a href="/">← Try Again</a>
    
    {}
</body>
</html>
            "#,
                get_common_styles(),
                error_response.error,
                get_footer_html()
            ))
        }
    }
}

async fn shorten_url(db: DbState, url: String) -> Result<UrlResponse, ErrorResponse> {
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
        let db_lock = db.lock().await;

        // Check if short code already exists
        let exists: bool = db_lock
            .prepare("SELECT 1 FROM urls WHERE short_code = ?1")
            .and_then(|mut stmt| stmt.query_row([&short_code], |_| Ok(true)))
            .unwrap_or(false);

        if !exists {
            // Insert new URL mapping
            let result = db_lock.execute(
                "INSERT INTO urls (short_code, original_url) VALUES (?1, ?2)",
                [&short_code, &url],
            );

            drop(db_lock); // Release the lock

            match result {
                Ok(_) => {
                    let response = UrlResponse {
                        original_url: url,
                        short_code: short_code.clone(),
                        short_url: format!("http://127.0.0.1:3000/{}", short_code),
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

        drop(db_lock); // Release the lock before next iteration
        attempts += 1;

        if attempts >= max_attempts {
            return Err(ErrorResponse {
                error: "Unable to generate unique short code".to_string(),
            });
        }
    }
}

async fn redirect_url(
    Path(short_code): Path<String>,
    State(db): State<DbState>,
) -> Result<Redirect, StatusCode> {
    let db_lock = db.lock().await;

    let result = db_lock
        .prepare("SELECT original_url FROM urls WHERE short_code = ?1")
        .and_then(|mut stmt| {
            stmt.query_row([&short_code], |row| {
                let original_url: String = row.get(0)?;
                Ok(original_url)
            })
        });

    drop(db_lock);

    match result {
        Ok(original_url) => {
            tracing::debug!("Redirecting {} -> {}", short_code, original_url);
            Ok(Redirect::permanent(&original_url))
        }
        Err(_) => {
            tracing::warn!("Short code not found: {}", short_code);
            Err(StatusCode::NOT_FOUND)
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
