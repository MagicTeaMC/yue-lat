# yue.lat 🔗

A fast, lightweight URL shortener built with Rust.

## 🚀 Quick Start

### Prerequisites

- [Rust](https://rustup.rs/) (1.70.0 or later)
- [Cargo](https://doc.rust-lang.org/cargo/) (comes with Rust)

### Installation

1. Clone the repository:
```bash
git clone https://github.com/MagicTeaMC/yue-lat.git
cd yue-lat
```

2. Run the application:
```bash
cargo run
```

The server will start on `http://localhost:3000` by default.

## ⚙️ Configuration

Configure the application using environment variables:

```bash
# Set custom port (default: 3000)
export PORT=8080
# Set base URL (default: https://yue.lat)
export BASE_URL=https://maoyue.tw

# Or use a .env file
echo "PORT=8080" > .env
```

## 📖 Usage

### Web Interface

Visit `http://localhost:3000` in your browser to access the web interface. Simply enter a URL and click "Shorten" to generate a short link.

### API Endpoints

#### Shorten a URL

**POST** `/shorten`

```bash
curl -X POST http://localhost:3000/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "original_url": "https://example.com",
  "short_code": "abc123",
  "short_url": "https://yue.lat/abc123"
}
```

#### Access Shortened URL

**GET** `/{short_code}`

Redirects to the original URL with a 301 Permanent Redirect.

```bash
curl -I http://localhost:3000/abc123
```

## 🏗️ Architecture

- **Framework**: [Axum](https://github.com/tokio-rs/axum) - Fast, ergonomic web framework
- **Database**: [SQLite](https://www.sqlite.org/) with [rusqlite](https://github.com/rusqlite/rusqlite)
- **Async Runtime**: [Tokio](https://tokio.rs/) for high-performance async I/O
- **Logging**: [tracing](https://github.com/tokio-rs/tracing) for structured logging
- **Serialization**: [serde](https://serde.rs/) for JSON handling

### Database Schema

```sql
CREATE TABLE urls (
    short_code TEXT PRIMARY KEY,
    original_url TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
```

## 📦 Deployment

### Docker

Create a `Dockerfile`:

```dockerfile
FROM rust:1.87 as builder
WORKDIR /app
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/yue-lat .
EXPOSE 3000
CMD ["./yue-lat"]
```

Build and run:
```bash
docker build -t yue-lat .
docker run -p 3000:3000 yue-lat
```

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 📞 Connect

- **GitHub**: [MagicTeaMC/yue-lat](https://github.com/MagicTeaMC/yue-lat)
- **Discord**: [Join our community](https://discord.gg/uQ4UXANnP2)

---

Made with 🦀 Rust and ❤️