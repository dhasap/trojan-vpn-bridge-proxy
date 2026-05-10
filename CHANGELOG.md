# Changelog

## [1.1.0] - 2026-05-11

### Added
- Howdy/OpenConnect/AnyConnect VPN source support via a dedicated `howdy-bridge` image.
- Smart Trojan import that probes common WS/TCP/gRPC transport variants before saving.
- Authenticated SOCKS5H copy URL and terminal test command in proxy cards.
- Mobile-friendly dashboard refresh with source badges, health summary, and filters.
- `.env.example` for safer deployment configuration.

### Changed
- Project/repository name updated to `vpn-bridge-proxy`.
- Compose defaults now use placeholder-safe values instead of deployment secrets.

### Security
- Ignored ACME challenge files, certificate backups, and private htpasswd files.
- Removed deployment-specific private gateway config from the committed compose/nginx templates.

## [1.0.0] - 2026-05-10

### Added
- Initial release
- Multi-user authentication with JWT
- Trojan URL parser
- Manual proxy configuration
- Docker container isolation per proxy
- Automatic port allocation (20000-30000)
- Proxy testing (IP + latency)
- SOCKS5 and HTTP proxy support
- Web dashboard with real-time status
- Start/Stop/Delete proxy management
- Copy proxy format with one click
- Admin panel for user management
- SQLite database for data persistence
- Nginx reverse proxy with SSL
- Docker Compose deployment

### Security
- JWT token authentication
- Password hashing with SHA-256
- Docker container isolation
- Non-root container execution
- SSL/TLS encryption
