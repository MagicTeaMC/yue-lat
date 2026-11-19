use anyhow::Result;
use clap::{Parser, Subcommand};
use sqlx::Row;

#[derive(Parser)]
#[command(
    name = "quickgo",
    version,
    about = "QuickGo server and local administration"
)]
pub struct Cli {
    /// SQLite file shared by the service and local commands. Prefer an absolute path.
    #[arg(long, global = true, env = "DATABASE_PATH", default_value = "urls.db")]
    pub database_path: String,
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Run the public HTTP service; applies database migrations on startup.
    Serve,
    /// Validate service configuration and existing database without modifying it.
    Check,
    /// Initialize or migrate the database without running the server.
    Migrate,
    /// Inspect and revoke links locally. Destinations cannot be edited.
    Link {
        #[command(subcommand)]
        command: LinkCommand,
    },
    /// Manage API keys locally. Full keys are displayed only on creation.
    ApiKey {
        #[command(subcommand)]
        command: KeyCommand,
    },
}

#[derive(Subcommand)]
pub enum LinkCommand {
    Show {
        code: String,
    },
    Revoke {
        code: String,
        #[arg(long)]
        reason: String,
    },
}

#[derive(Subcommand)]
pub enum KeyCommand {
    Create {
        #[arg(long)]
        name: String,
    },
    List,
    Revoke {
        id: i64,
    },
}

pub async fn run_local(cli: &Cli) -> Result<()> {
    use crate::db;
    if matches!(cli.command, Command::Check) {
        crate::service_config()?;
        db::check(&cli.database_path).await?;
        println!("Configuration and database OK: {}", cli.database_path);
        return Ok(());
    }
    if matches!(cli.command, Command::Migrate) {
        let db = db::setup(&cli.database_path).await?;
        db.close().await;
        println!("Database ready: {}", cli.database_path);
        return Ok(());
    }
    // Other commands require an existing, up-to-date database.
    db::check(&cli.database_path).await?;
    let pool = db::open(&cli.database_path, false).await?;
    match &cli.command {
        Command::ApiKey { command } => match command {
            KeyCommand::Create { name } => {
                let (id, key) = db::create_key(&pool, name).await?;
                eprintln!("Created API key ID {id}. Store this key now; it cannot be shown again.");
                println!("{key}");
            }
            KeyCommand::List => {
                let rows = sqlx::query(
                    "SELECT id, name, created_at, revoked_at FROM api_keys ORDER BY id",
                )
                .fetch_all(&pool)
                .await?;
                let values: Vec<_> = rows
                    .iter()
                    .map(|row| {
                        serde_json::json!({
                            "id": row.get::<i64, _>("id"),
                            "name": row.get::<String, _>("name"),
                            "created_at": row.get::<String, _>("created_at"),
                            "revoked_at": row.get::<Option<String>, _>("revoked_at"),
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&values)?);
            }
            KeyCommand::Revoke { id } => {
                db::revoke_key(&pool, *id).await?;
                println!("API key {id} revoked");
            }
        },
        Command::Link { command } => match command {
            LinkCommand::Show { code } => {
                let row = sqlx::query("SELECT short_code, original_url, created_at, revoked_at, revoke_reason FROM urls WHERE short_code = ?")
                    .bind(code).fetch_optional(&pool).await?.ok_or_else(|| anyhow::anyhow!("Short code not found"))?;
                println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "short_code": row.get::<String, _>("short_code"),
                        "original_url": row.get::<String, _>("original_url"),
                        "created_at": row.get::<Option<String>, _>("created_at"),
                        "revoked_at": row.get::<Option<String>, _>("revoked_at"),
                        "revoke_reason": row.get::<Option<String>, _>("revoke_reason"),
                    }))?
                );
            }
            LinkCommand::Revoke { code, reason } => {
                db::revoke_link(&pool, code, reason).await?;
                println!("Link {code} revoked");
            }
        },
        _ => unreachable!(),
    }
    pool.close().await;
    Ok(())
}
