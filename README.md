# Trojan VPN Bridge Proxy

Convert Trojan VPN connections to standard SOCKS5/HTTP proxy with web management panel.

## Features

- **Multi-user Support** - Each user has their own proxy accounts
- **JWT Authentication** - Secure login with session tokens
- **Trojan URL Parser** - Automatically parse Trojan URLs
- **Manual Configuration** - Input proxy details manually
- **Docker Isolation** - Each proxy runs in its own container
- **Port Allocation** - Automatic port assignment (20000-30000)
- **Proxy Testing** - Check IP and latency
- **Copy Format** - One-click copy proxy format

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        User                                 │
│                          │                                  │
│                          ▼                                  │
│                    ┌──────────┐                             │
│                    │  Nginx   │ (SSL + Reverse Proxy)       │
│                    └────┬─────┘                             │
│                         │                                   │
│              ┌──────────┴──────────┐                        │
│              ▼                     ▼                        │
│        ┌──────────┐         ┌──────────┐                   │
│        │  Panel   │         │  Xray    │ (per proxy)       │
│        │ (FastAPI)│         │ Container│                   │
│        └──────────┘         └────┬─────┘                   │
│              │                   │                          │
│              ▼                   ▼                          │
│        ┌──────────┐         ┌──────────┐                   │
│        │  SQLite  │         │ Trojan   │                   │
│        │ Database │         │  Server  │                   │
│        └──────────┘         └──────────┘                   │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/dhasap/trojan-vpn-bridge-proxy.git
cd trojan-vpn-bridge-proxy
```

### 2. Configure Environment

Edit `docker-compose.yml`:

```yaml
environment:
  - SECRET_KEY=your-secret-key-here
  - VPS_IP=your-vps-ip
  - PORT_START=20000
  - PORT_END=30000
```

### 3. Add SSL Certificates

Place your SSL certificates in `certs/`:

```bash
cp /path/to/fullchain.pem certs/
cp /path/to/privkey.pem certs/
```

Or generate self-signed:

```bash
openssl req -x509 -nodes -days 3650 -newkey rsa:2048 \
  -keyout certs/privkey.pem \
  -out certs/fullchain.pem \
  -subj "/CN=your-domain.com"
```

### 4. Start Services

```bash
docker compose up -d
```

### 5. Access Panel

Open `https://your-domain.com` in browser.

## Default Login

| Field | Value |
|-------|-------|
| Username | admin |
| Password | admin123 |

**⚠️ Change password immediately after first login!**

## Usage

### Adding Proxy via URL

1. Click "Add Proxy" in dashboard
2. Select "Paste URL" tab
3. Paste Trojan URL:
   ```
   trojan://password@host:port/?sni=xxx&type=ws&host=xxx&path=/howdy
   ```
4. Click "Add Proxy"

### Adding Proxy Manually

1. Click "Add Proxy" in dashboard
2. Select "Manual Input" tab
3. Fill in:
   - Password: Trojan password
   - Host: Trojan server host
   - Port: Trojan server port (default: 443)
   - SNI: Server Name Indication
   - Network: WebSocket/TCP/gRPC
   - WS Path: WebSocket path
4. Click "Add Proxy"

### Starting Proxy

1. Click "Start" button on proxy card
2. Wait for container to start
3. Copy proxy format from the card

### Proxy Format

After starting, you get:

```
Format: IP:PORT:USER:PASSWORD
Example: 8.222.230.139:20002:proxy:abc123def456

SOCKS5 URL: socks5://USER:PASSWORD@IP:PORT
Example: socks5://proxy:abc123def456@8.222.230.139:20002

HTTP Proxy: http://USER:PASSWORD@IP:PORT
Example: http://proxy:abc123def456@8.222.230.139:20002
```

### Using Proxy from Other VPS

```bash
# Using curl
curl -x socks5://proxy:abc123def456@8.222.230.139:20002 https://httpbin.org/ip

# Using wget
wget -e use_proxy=yes -e http_proxy=socks5://proxy:abc123def456@8.222.230.139:20002 https://httpbin.org/ip

# In Python
import requests
proxies = {'http': 'socks5://proxy:abc123def456@8.222.230.139:20002'}
r = requests.get('https://httpbin.org/ip', proxies=proxies)
```

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | /api/auth/register | Register new user |
| POST | /api/auth/login | Login |
| GET | /api/auth/me | Get current user |
| GET | /api/auth/logout | Logout |

### Proxies

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/proxies | List user's proxies |
| POST | /api/proxies | Add new proxy |
| GET | /api/proxies/:id | Get proxy details |
| POST | /api/proxies/:id/start | Start proxy |
| POST | /api/proxies/:id/stop | Stop proxy |
| DELETE | /api/proxies/:id | Delete proxy |
| POST | /api/proxies/:id/test | Test proxy |

### Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | /api/admin/users | List all users |
| DELETE | /api/admin/users/:id | Delete user |
| GET | /api/stats | Get statistics |

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| SECRET_KEY | trojan-panel-secret-key-2026 | JWT secret key |
| DB_PATH | /app/data/panel.db | SQLite database path |
| VPS_IP | 8.222.230.139 | VPS public IP |
| PORT_START | 20000 | Port range start |
| PORT_END | 30000 | Port range end |
| XRAY_IMAGE | teddysun/xray:latest | Xray Docker image |
| XRAY_CONFIGS_HOST | /opt/trojan-panel/xray-configs | Host path for configs |

## Firewall Configuration

### iptables

```bash
# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Allow proxy port range
iptables -A INPUT -p tcp --dport 20000:30000 -j ACCEPT

# Save rules
netfilter-persistent save
```

### Alibaba Cloud Security Group

Add inbound rules:

| Port Range | Protocol | Source | Action |
|------------|----------|--------|--------|
| 80/80 | TCP | 0.0.0.0/0 | Allow |
| 443/443 | TCP | 0.0.0.0/0 | Allow |
| 20000/30000 | TCP | 0.0.0.0/0 | Allow |

## Database Schema

### users

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| username | TEXT | Username (unique) |
| password_hash | TEXT | Hashed password |
| role | TEXT | User role (user/admin) |
| created_at | TIMESTAMP | Creation time |

### proxies

| Column | Type | Description |
|--------|------|-------------|
| id | INTEGER | Primary key |
| user_id | INTEGER | Foreign key to users |
| name | TEXT | Proxy name |
| trojan_raw_url | TEXT | Original Trojan URL |
| trojan_password | TEXT | Trojan password |
| trojan_host | TEXT | Trojan server host |
| trojan_port | INTEGER | Trojan server port |
| trojan_sni | TEXT | SNI value |
| network_type | TEXT | Network type (ws/tcp/grpc) |
| ws_host | TEXT | WebSocket host |
| ws_path | TEXT | WebSocket path |
| container_name | TEXT | Docker container name |
| local_port | INTEGER | Allocated port |
| status | TEXT | RUNNING/PAUSED/STOPPED/ERROR |
| proxy_user | TEXT | SOCKS5 username |
| proxy_pass | TEXT | SOCKS5 password |
| last_test_ip | TEXT | Last test IP result |
| last_test_ping | INTEGER | Last test latency (ms) |
| last_test_time | TIMESTAMP | Last test time |
| created_at | TIMESTAMP | Creation time |

## Troubleshooting

### Container not starting

```bash
# Check container logs
docker logs proxy_USER_ID

# Check Xray config
cat xray-configs/proxy_ID/config.json

# Restart container
docker restart proxy_USER_ID
```

### Proxy not accessible

1. Check if port is open:
   ```bash
   ss -tlnp | grep PORT
   ```

2. Check firewall:
   ```bash
   iptables -L INPUT -n | grep PORT
   ```

3. Check Alibaba Cloud Security Group

### Database issues

```bash
# Access database
docker exec -it panel-backend sqlite3 /app/data/panel.db

# List users
SELECT * FROM users;

# List proxies
SELECT * FROM proxies;
```

## Development

### Project Structure

```
trojan-vpn-bridge-proxy/
├── backend/
│   ├── main.py          # FastAPI application
│   └── requirements.txt # Python dependencies
├── frontend/
│   ├── index.html       # Landing page
│   ├── login.html       # Login page
│   ├── register.html    # Register page
│   ├── dashboard.html   # Main dashboard
│   └── static/
│       ├── css/
│       │   └── style.css
│       └── js/
│           └── app.js
├── nginx/
│   └── nginx.conf       # Nginx configuration
├── certs/               # SSL certificates (gitignored)
├── data/                # Database (gitignored)
├── xray-configs/        # Xray configs (gitignored)
├── docker-compose.yml
├── Dockerfile
├── .gitignore
└── README.md
```

### Running Locally

```bash
# Install dependencies
cd backend
pip install -r requirements.txt

# Run backend
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Access at http://localhost:8000
```

## License

MIT License

## Credits

- [Xray-core](https://github.com/XTLS/Xray-core) - Proxy engine
- [FastAPI](https://fastapi.tiangolo.com/) - Backend framework
- [teddysun/xray](https://hub.docker.com/r/teddysun/xray) - Docker image
