# qkgo 🔗

A lightweight URL shortener built with Rust, Axum, and SQLite, for https://qkgo.de.
The source repository and executable retain the `yue-lat` name.

## Run locally

1. Install stable Rust with support for edition 2024.
2. Clone this repository and enter its directory.
3. Copy `.env.example` to `.env`.
4. Generate **two independent secrets** with `openssl rand -hex 32`: use one for
   `API_KEYS` and the other for `ALTCHA_SECRET`. No working secrets are shipped.
5. Set `BASE_URL=http://localhost:3000` for local development.
6. Run `cargo run --locked` and open http://localhost:3000.

For a release build, run `cargo build --release --locked`, then start
`./target/release/yue-lat` from the repository directory so `static/` is available.
HTML templates are compiled into the executable.

## Configuration

Existing environment variables take precedence over an optional `.env` file.
A malformed `.env` fails startup; a missing file is allowed.

| Variable | Default | Description |
| --- | --- | --- |
| `PORT` | `3000` | Listen port on `0.0.0.0` |
| `BASE_URL` | `https://qkgo.de` | Public HTTP(S) origin; no credentials, path, query, or fragment |
| `DATABASE_PATH` | `urls.db` | SQLite file; its parent directory must already exist |
| `API_KEYS` | Required | Comma-separated, nonempty API keys |
| `ALTCHA_SECRET` | Required | Nonempty secret for form challenges |

New links use six case-sensitive alphanumeric characters. Existing four-character
links remain readable. Changing `BASE_URL` changes newly returned short URLs and
page metadata, without changing stored mappings. Short codes are not passwords.

## API

Documentation is available at `/api/v1`. Create links with:

```sh
curl https://qkgo.de/api/v1/shorten \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/path"}'
```

Only HTTP and HTTPS destination URLs are accepted. Successful creation returns
HTTP 201 with `original_url`, `short_code`, and `short_url`. The public web form
uses CSRF protection and ALTCHA; API creation requires a configured API key.

## Deployment and data

- Point `qkgo.de` at your server and terminate HTTPS at a reverse proxy.
- Set `BASE_URL=https://qkgo.de` and keep the application port behind that proxy.
- Set `DATABASE_PATH` to a persistent location. Do not start against an empty
  path by accident when moving or restarting the service.
- Back up using SQLite's online backup facilities or `VACUUM INTO`, and keep a
  copy off the server. Verify restoration before launch. Do not copy only the
  live `urls.db` while ignoring its WAL.
- Existing data can be used directly; this update does not alter the table schema.

Before reopening public creation, add rate limits and quotas at the proxy or
application level. This version does not implement rate limiting, single-use
CAPTCHA challenges, or an administrative link-disable workflow. Redirects still
use HTTP 308; consider cache and revocation requirements before public launch.

## Development

```sh
cargo fmt --check
cargo test --locked
```

Tests cover configurable origins, templates, collision retries and exhaustion,
database errors, six-character creation, and existing four-character redirects.

## Contributing

Pull requests are welcome. For major changes, open an issue first.
