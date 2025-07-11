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

# Set base URL for generated links (default: https://yue.lat)
export BASE_URL=https://maoyue.tw

# Or use a .env file
echo "PORT=8080" > .env
echo "BASE_URL=https://maoyue.tw" >> .env
```

## 📖 Usage

### Web Interface

Visit `http://localhost:3000` in your browser to access the web interface. Simply enter a URL and click "Shorten" to generate a short link.

### API Endpoints

#### Shorten a URL
**POST** `/api/v1/shorten`

```bash
curl -X POST http://localhost:3000/api/v1/shorten \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

**Response:**
```json
{
  "original_url": "https://example.com",
  "short_code": "aBc4",
  "short_url": "https://yue.lat/aBc4"
}
```

#### Access Shortened URL
**GET** `/{short_code}`

Redirects to the original URL with a 301 Permanent Redirect.

```bash
curl -I http://localhost:3000/aBc4
# HTTP/1.1 301 Moved Permanently
# Location: https://example.com
```

## 🏗️ Architecture

### Database Schema
```sql
CREATE TABLE urls (
    short_code TEXT PRIMARY KEY CHECK(length(short_code) <= 20),
    original_url TEXT NOT NULL CHECK(length(original_url) <= 2048),
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
docker run -p 3000:3000 -e BASE_URL=https://yourdomain.com yue-lat
```

### Environment Variables for Production
```bash
PORT=3000
BASE_URL=https://yourdomain.com
RUST_LOG=info
```

## 🤝 Contributing

We welcome contributions! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

## 📝 License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## 📞 Connect

- **GitHub**: [MagicTeaMC/yue-lat](https://github.com/MagicTeaMC/yue-lat)
- **Discord**: [Join our community](https://discord.gg/uQ4UXANnP2)

---

Made with 🦀 Rust and ❤️