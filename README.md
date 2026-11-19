# QuickGo 🔗

A fast, lightweight URL shortener built with Rust. Previously yue.lat.

## 🚀 Quick Start
### API
Check out <https://qkgo.de/api/v1>

### Self-host
1. Clone this repo
2. `cargo build --release --locked`
3. `cp .env.example .env`
4. Edit `.env`; generate `ALTCHA_SECRET` with `openssl rand -hex 32`
5. Run `./target/release/quickgo migrate`, then `./target/release/quickgo serve`

### Management
Run on the server, using the same `DATABASE_PATH` as the service:

```sh
quickgo check
quickgo api-key create --name my-bot
quickgo api-key list
quickgo api-key revoke <id>
quickgo link show <code>
quickgo link revoke <code> --reason "abuse report"
```

API keys are shown only once. Remove old `API_KEYS` environment settings before starting.

## 🤝 Contributing
We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

---

Made with 🦀 Rust and ❤️
