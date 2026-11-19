use std::{
    path::PathBuf,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

struct Database(PathBuf);
impl Database {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
                "quickgo-cli-{}-{}.db",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            )))
    }
    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_quickgo"))
            .arg("--database-path")
            .arg(&self.0)
            .args(args)
            .env("ALTCHA_SECRET", "integration-test-secret")
            .env_remove("API_KEYS")
            .env_remove("BASE_URL")
            .env_remove("PORT")
            .current_dir(self.0.parent().unwrap())
            .output()
            .unwrap()
    }
}
impl Drop for Database {
    fn drop(&mut self) {
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", self.0.display()));
        }
    }
}

#[test]
fn cli_manages_keys_across_processes_without_revealing_them_in_lists() {
    let db = Database::new();
    assert!(!db.run(&["check"]).status.success());
    assert!(!db.0.exists(), "check created a database");
    assert!(!db.run(&["api-key", "list"]).status.success());
    assert!(!db.0.exists(), "list created a database");
    let migrate = db.run(&["migrate"]);
    assert!(
        migrate.status.success(),
        "{}",
        String::from_utf8_lossy(&migrate.stderr)
    );
    assert!(db.run(&["check"]).status.success());
    let create = db.run(&["api-key", "create", "--name", "test-bot"]);
    assert!(
        create.status.success(),
        "{}",
        String::from_utf8_lossy(&create.stderr)
    );
    let key = String::from_utf8(create.stdout).unwrap();
    assert!(key.trim().starts_with("qkg_"));
    let list = db.run(&["api-key", "list"]);
    assert!(list.status.success());
    let list = String::from_utf8(list.stdout).unwrap();
    assert!(!list.contains(key.trim()));
    assert!(!list.contains("key_hash"));
    let rows: serde_json::Value = serde_json::from_str(&list).unwrap();
    assert_eq!(rows[0]["name"], "test-bot");
    let id = rows[0]["id"].as_i64().unwrap().to_string();
    assert!(db.run(&["api-key", "revoke", &id]).status.success());
    let list: serde_json::Value =
        serde_json::from_slice(&db.run(&["api-key", "list"]).stdout).unwrap();
    assert!(list[0]["revoked_at"].is_string());
    assert!(!db.run(&["api-key", "revoke", "999999"]).status.success());
    assert!(
        !db.run(&["api-key", "create", "--name", " "])
            .status
            .success()
    );
    assert!(!db.run(&["link", "show", "missing"]).status.success());
    assert!(
        !db.run(&["link", "revoke", "missing", "--reason", "abuse"])
            .status
            .success()
    );
    assert!(!db.run(&["link", "edit", "abcd"]).status.success());
}
