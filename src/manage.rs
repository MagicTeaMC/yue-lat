use askama::Template;
use axum::{
    Extension, Form, Json,
    extract::{ConnectInfo, Path, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_csrf::CsrfToken;
use base64::{Engine, prelude::BASE64_URL_SAFE_NO_PAD};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::{QueryBuilder, Sqlite};
use std::net::SocketAddr;

use crate::{
    ApiKeyId, AppState, ErrorResponse, FormSecurity, HtmlError, api_error, database_error, db,
    invalid_api_key, json_error, normalize_destination, parse_form_expiration,
    parse_form_max_visits, render_html, validate_expiration, validate_max_visits,
    verify_sensitive_form,
};

type ManagementError = (StatusCode, ErrorResponse);

#[derive(sqlx::FromRow, Serialize)]
pub struct LinkInfo {
    short_code: String,
    original_url: String,
    expires_at: Option<i64>,
    has_password: bool,
    max_visits: Option<i64>,
    visit_count: i64,
    paused: bool,
    updated_at: Option<String>,
    #[serde(skip)]
    revoked: bool,
}

const INFO_COLUMNS: &str =
    "short_code, original_url, expires_at, password_hash IS NOT NULL AS has_password,
    max_visits, visit_count, paused, updated_at, revoked_at IS NOT NULL AS revoked";

struct EditTokenHash {
    hash: String,
    short_code: Option<String>,
}

impl EditTokenHash {
    fn parse(token: &str) -> Result<Self, ManagementError> {
        let token = token.trim();
        let valid = token.strip_prefix("qke_").is_some_and(|secret| {
            secret.len() == 43
                && BASE64_URL_SAFE_NO_PAD
                    .decode(secret)
                    .is_ok_and(|bytes| bytes.len() == 32)
        });
        if !valid {
            return Err(edit_token_not_found());
        }
        Ok(Self {
            hash: db::hash_key(token),
            short_code: None,
        })
    }
}

enum LinkAccess {
    Token(EditTokenHash),
    ApiKey { code: String, id: ApiKeyId },
}

impl LinkAccess {
    fn push_filter(&self, query: &mut QueryBuilder<Sqlite>) {
        match self {
            Self::Token(token) => {
                query.push("edit_token_hash = ").push_bind(&token.hash);
                if let Some(code) = &token.short_code {
                    query.push(" AND short_code = ").push_bind(code);
                }
            }
            Self::ApiKey { code, id } => {
                query.push("short_code = ").push_bind(code);
                query.push(" AND created_by_api_key_id = ").push_bind(id.0);
                query.push(" AND EXISTS (SELECT 1 FROM api_keys WHERE id = created_by_api_key_id AND revoked_at IS NULL)");
            }
        }
    }

    async fn missing(&self, app: &AppState) -> ManagementError {
        if let Self::ApiKey { id, .. } = self {
            let active = sqlx::query_scalar::<_, i64>(
                "SELECT id FROM api_keys WHERE id = ? AND revoked_at IS NULL",
            )
            .bind(id.0)
            .fetch_optional(&app.db)
            .await;
            match active {
                Ok(None) => return invalid_api_key(),
                Err(error) => return database_error(error),
                Ok(Some(_)) => {}
            }
        }
        match self {
            Self::Token(_) => edit_token_not_found(),
            Self::ApiKey { .. } => {
                api_error(StatusCode::NOT_FOUND, "No link found for these credentials")
            }
        }
    }
}

fn edit_token_not_found() -> ManagementError {
    api_error(StatusCode::NOT_FOUND, "Unable to manage this link.")
}

async fn find_link(app: &AppState, access: &LinkAccess) -> Result<LinkInfo, ManagementError> {
    let mut query = QueryBuilder::new("SELECT ");
    query.push(INFO_COLUMNS).push(" FROM urls WHERE ");
    access.push_filter(&mut query);
    let info: Option<LinkInfo> = query
        .build_query_as()
        .fetch_optional(&app.db)
        .await
        .map_err(database_error)?;
    let Some(info) = info else {
        return Err(access.missing(app).await);
    };
    if info.revoked {
        return Err(api_error(
            StatusCode::GONE,
            "This link has been permanently revoked.",
        ));
    }
    Ok(info)
}

#[derive(Default)]
struct EditSettings {
    url: Option<String>,
    expires_at: Option<Option<i64>>,
    max_visits: Option<Option<i64>>,
    password: Option<Option<String>>,
    paused: Option<bool>,
}

async fn update_link(
    app: &AppState,
    access: &LinkAccess,
    current: LinkInfo,
    settings: EditSettings,
) -> Result<LinkInfo, ManagementError> {
    if settings.url.is_none()
        && settings.expires_at.is_none()
        && settings.max_visits.is_none()
        && settings.password.is_none()
        && settings.paused.is_none()
    {
        return Ok(current);
    }
    if let Some(expiration) = settings.expires_at {
        validate_expiration(expiration)?;
    }
    if let Some(max_visits) = settings.max_visits {
        validate_max_visits(max_visits)?;
    }

    let mut query = QueryBuilder::new("UPDATE urls SET updated_at = CURRENT_TIMESTAMP");
    if let Some(url) = settings.url {
        query
            .push(", original_url = ")
            .push_bind(normalize_destination(&url, &app.base_url)?);
    }
    if let Some(expiration) = settings.expires_at {
        query.push(", expires_at = ").push_bind(expiration);
    }
    if let Some(max_visits) = settings.max_visits {
        query.push(", max_visits = ").push_bind(max_visits);
    }
    if let Some(password) = settings.password {
        let hash = match password {
            Some(password) => Some(app.security.password_work.hash(password).await?),
            None => None,
        };
        query.push(", password_hash = ").push_bind(hash);
    }
    if let Some(paused) = settings.paused {
        query.push(", paused = ").push_bind(paused);
    }
    // Recheck the credential and permanent revocation in the write itself.
    query.push(" WHERE revoked_at IS NULL AND ");
    access.push_filter(&mut query);
    query.push(" RETURNING ").push(INFO_COLUMNS);
    match query
        .build_query_as()
        .fetch_optional(&app.db)
        .await
        .map_err(database_error)?
    {
        Some(info) => Ok(info),
        None => find_link(app, access).await,
    }
}

#[derive(Template)]
#[template(path = "edit.html")]
struct EditTemplate {
    security: FormSecurity,
    link: Option<LinkInfo>,
    expiration: String,
    max_visits: String,
    expired: bool,
    exhausted: bool,
    saved: bool,
}

fn edit_page(
    app: &AppState,
    token: CsrfToken,
    link: Option<LinkInfo>,
    saved: bool,
) -> Result<Response, HtmlError> {
    let expiration = link
        .as_ref()
        .and_then(|info| info.expires_at)
        .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0))
        .map(|value| value.format("%Y-%m-%dT%H:%M:%S").to_string())
        .unwrap_or_default();
    let max_visits = link
        .as_ref()
        .and_then(|info| info.max_visits)
        .map(|value| value.to_string())
        .unwrap_or_default();
    let expired = link
        .as_ref()
        .and_then(|info| info.expires_at)
        .is_some_and(|expiry| expiry <= Utc::now().timestamp());
    let exhausted = link.as_ref().is_some_and(|info| {
        info.max_visits
            .is_some_and(|maximum| info.visit_count >= maximum)
    });
    let template = EditTemplate {
        security: FormSecurity::new(app, &token)?,
        link,
        expiration,
        max_visits,
        expired,
        exhausted,
        saved,
    };
    Ok((token, render_html(template)?).into_response())
}

pub async fn edit_form(
    token: CsrfToken,
    State(app): State<AppState>,
) -> Result<Response, HtmlError> {
    edit_page(&app, token, None, false)
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum EditAction {
    Lookup,
    Save,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PasswordAction {
    #[default]
    Keep,
    Set,
    Remove,
}

#[derive(Deserialize)]
pub struct EditForm {
    action: EditAction,
    edit_token: String,
    #[serde(default)]
    authenticity_token: String,
    #[serde(default)]
    altcha: String,
    short_code: Option<String>,
    url: Option<String>,
    expires_at: Option<String>,
    max_visits: Option<String>,
    #[serde(default)]
    update_enabled: bool,
    #[serde(default)]
    enabled: bool,
    #[serde(default)]
    password_action: PasswordAction,
    #[serde(default)]
    password: String,
}

pub async fn submit_edit(
    token: CsrfToken,
    State(app): State<AppState>,
    peer: Option<Extension<ConnectInfo<SocketAddr>>>,
    Form(form): Form<EditForm>,
) -> Result<Response, HtmlError> {
    verify_sensitive_form(&app, &token, &form.authenticity_token, &form.altcha).await?;
    app.security
        .edit_attempts
        .check(peer.map(|Extension(ConnectInfo(addr))| addr.ip()))?;
    let mut access = EditTokenHash::parse(&form.edit_token)?;
    match form.action {
        EditAction::Lookup => {
            let link = find_link(&app, &LinkAccess::Token(access)).await?;
            edit_page(&app, token, Some(link), false)
        }
        EditAction::Save => {
            access.short_code = Some(form.short_code.ok_or_else(edit_token_not_found)?);
            let access = LinkAccess::Token(access);
            let current = find_link(&app, &access).await?;
            let settings = EditSettings {
                url: form.url,
                expires_at: form
                    .expires_at
                    .as_deref()
                    .map(parse_form_expiration)
                    .transpose()?,
                max_visits: form
                    .max_visits
                    .as_deref()
                    .map(parse_form_max_visits)
                    .transpose()?,
                paused: form.update_enabled.then_some(!form.enabled),
                password: match form.password_action {
                    PasswordAction::Keep => None,
                    PasswordAction::Set => Some(Some(form.password)),
                    PasswordAction::Remove => Some(None),
                },
            };
            let link = update_link(&app, &access, current, settings).await?;
            edit_page(&app, token, Some(link), true)
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchLink {
    #[serde(default, deserialize_with = "present")]
    url: Option<Option<String>>,
    #[serde(default, deserialize_with = "present")]
    expires_at: Option<Option<i64>>,
    #[serde(default, deserialize_with = "present")]
    max_visits: Option<Option<i64>>,
    #[serde(default, deserialize_with = "present")]
    password: Option<Option<String>>,
    #[serde(default, deserialize_with = "present_bool")]
    paused: Option<bool>,
}

// Serde uses the default for an omitted field. A present JSON null is an explicit clear.
fn present<'de, D, T>(value: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de>,
{
    Option::deserialize(value).map(Some)
}

fn present_bool<'de, D>(value: D) -> Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    bool::deserialize(value).map(Some)
}

pub async fn get_link(
    State(app): State<AppState>,
    Extension(id): Extension<ApiKeyId>,
    Path(code): Path<String>,
) -> Result<Json<LinkInfo>, (StatusCode, Json<ErrorResponse>)> {
    find_link(&app, &LinkAccess::ApiKey { code, id })
        .await
        .map(Json)
        .map_err(json_error)
}

pub async fn patch_link(
    State(app): State<AppState>,
    Extension(id): Extension<ApiKeyId>,
    Path(code): Path<String>,
    Json(patch): Json<PatchLink>,
) -> Result<Json<LinkInfo>, (StatusCode, Json<ErrorResponse>)> {
    let access = LinkAccess::ApiKey { code, id };
    let current = find_link(&app, &access).await.map_err(json_error)?;
    let url = patch
        .url
        .map(|value| {
            value.ok_or_else(|| {
                json_error(api_error(
                    StatusCode::BAD_REQUEST,
                    "Destination cannot be null",
                ))
            })
        })
        .transpose()?;
    let settings = EditSettings {
        url,
        expires_at: patch.expires_at,
        max_visits: patch.max_visits,
        password: patch.password,
        paused: patch.paused,
    };
    update_link(&app, &access, current, settings)
        .await
        .map(Json)
        .map_err(json_error)
}
