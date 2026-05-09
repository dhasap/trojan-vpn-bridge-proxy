#!/usr/bin/env python3
"""
Trojan Proxy Panel - Backend API
Multi-user proxy management with Docker orchestration
"""

import json, os, hashlib, time, re, sqlite3, subprocess, socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, urlparse, parse_qs

from fastapi import FastAPI, Request, Form, HTTPException, Depends, Cookie
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
import jwt

# ─── Config ───────────────────────────────────────────────

app = FastAPI(title="Trojan Proxy Panel")

SECRET_KEY = os.getenv("SECRET_KEY", "trojan-panel-secret-key-change-me-2026")
DB_PATH = os.getenv("DB_PATH", "/app/data/panel.db")
VPS_IP = os.getenv("VPS_IP", "8.222.230.139")
PORT_RANGE_START = int(os.getenv("PORT_START", "20000"))
PORT_RANGE_END = int(os.getenv("PORT_END", "30000"))
XRAY_IMAGE = os.getenv("XRAY_IMAGE", "teddysun/xray:latest")
XRAY_CONFIGS_HOST = os.getenv("XRAY_CONFIGS_HOST", "/opt/trojan-panel/xray-configs")
DATA_DIR = "/app/data"

os.makedirs(DATA_DIR, exist_ok=True)

# ─── Database ─────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn

def init_db():
    conn = get_db()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'user',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS proxies (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            name TEXT DEFAULT '',
            trojan_raw_url TEXT DEFAULT '',
            trojan_password TEXT NOT NULL,
            trojan_host TEXT NOT NULL,
            trojan_port INTEGER DEFAULT 443,
            trojan_sni TEXT DEFAULT '',
            network_type TEXT DEFAULT 'ws',
            ws_host TEXT DEFAULT '',
            ws_path TEXT DEFAULT '/',
            container_name TEXT DEFAULT '',
            local_port INTEGER DEFAULT 0,
            status TEXT DEFAULT 'STOPPED',
            last_test_ip TEXT DEFAULT '',
            last_test_ping INTEGER DEFAULT 0,
            last_test_time TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        );
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    # Create default admin if not exists
    admin = conn.execute("SELECT * FROM users WHERE username='admin'").fetchone()
    if not admin:
        pwd_hash = hashlib.sha256("admin123".encode()).hexdigest()
        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)", 
                     ("admin", pwd_hash, "admin"))
    conn.commit()
    conn.close()

init_db()

# ─── Auth Helpers ─────────────────────────────────────────

def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def gen_pass():
    """Generate random password"""
    import secrets
    return secrets.token_hex(8)

def create_token(user_id: int, username: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def verify_token(token: str) -> Optional[dict]:
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=["HS256"])
    except:
        return None

def get_current_user(request: Request) -> Optional[dict]:
    token = request.cookies.get("token")
    if not token:
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            token = auth[7:]
    if not token:
        return None
    return verify_token(token)

def require_user(request: Request) -> dict:
    user = get_current_user(request)
    if not user:
        raise HTTPException(401, "Not authenticated")
    return user

def require_admin(request: Request) -> dict:
    user = require_user(request)
    if user.get("role") != "admin":
        raise HTTPException(403, "Admin only")
    return user

# ─── Trojan URL Parser ────────────────────────────────────

def parse_trojan_url(url: str) -> dict:
    """
    Parse: trojan://password@host:port/?sni=xxx&type=ws&host=xxx&path=/howdy
    Returns dict with parsed fields
    """
    result = {
        "password": "",
        "host": "",
        "port": 443,
        "sni": "",
        "network_type": "ws",
        "ws_host": "",
        "ws_path": "/"
    }
    
    if not url.startswith("trojan://"):
        return result
    
    try:
        # Remove trojan:// prefix
        rest = url[9:]
        
        # Split password@host
        if "@" in rest:
            password, rest = rest.split("@", 1)
            result["password"] = unquote(password)
        else:
            return result
        
        # Split host:port?params
        if "?" in rest:
            host_part, params_part = rest.split("?", 1)
        else:
            host_part = rest
            params_part = ""
        
        # Parse host:port
        if ":" in host_part:
            host, port = host_part.rsplit(":", 1)
            result["host"] = host.strip("/")
            try:
                result["port"] = int(port)
            except:
                result["port"] = 443
        else:
            result["host"] = host_part.strip("/")
            result["port"] = 443
        
        # Parse query params
        params = parse_qs(params_part)
        result["sni"] = params.get("sni", [result["host"]])[0]
        result["network_type"] = params.get("type", ["ws"])[0]
        result["ws_host"] = params.get("host", [result["host"]])[0]
        result["ws_path"] = unquote(params.get("path", ["/"])[0])
        
        # If host is empty, use host from params or sni
        if not result["host"]:
            result["host"] = result["ws_host"] or result["sni"]
        
    except Exception as e:
        print(f"Parse error: {e}")
    
    return result

# ─── Port Allocator ───────────────────────────────────────

def find_available_port() -> int:
    """Find an available port in the configured range"""
    conn = get_db()
    used_ports = [row["local_port"] for row in 
                  conn.execute("SELECT local_port FROM proxies WHERE local_port > 0").fetchall()]
    conn.close()
    
    for port in range(PORT_RANGE_START, PORT_RANGE_END):
        if port not in used_ports:
            # Double-check port is actually free
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                sock.bind(("", port))
                sock.close()
                return port
            except:
                continue
    raise HTTPException(503, "No available ports")

# ─── Xray Config Generator ───────────────────────────────

def generate_xray_config(proxy_data: dict) -> dict:
    """Generate Xray-core config for a Trojan proxy"""
    password = proxy_data["trojan_password"]
    host = proxy_data["trojan_host"]
    port = proxy_data["trojan_port"]
    sni = proxy_data.get("trojan_sni", host)
    network = proxy_data.get("network_type", "ws")
    ws_host = proxy_data.get("ws_host", host)
    ws_path = proxy_data.get("ws_path", "/")
    
    # Generate proxy credentials
    proxy_user = "proxy"
    proxy_pass = gen_pass()
    
    config = {
        "log": {
            "loglevel": "warning"
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "port": 1080,
                "listen": "0.0.0.0",
                "protocol": "socks",
                "settings": {
                    "auth": "password",
                    "accounts": [
                        {
                            "user": proxy_user,
                            "pass": proxy_pass
                        }
                    ],
                    "udp": True
                }
            },
            {
                "tag": "http-in",
                "port": 1081,
                "listen": "0.0.0.0",
                "protocol": "http",
                "settings": {
                    "accounts": [
                        {
                            "user": proxy_user,
                            "pass": proxy_pass
                        }
                    ]
                }
            }
        ],
        "outbounds": [
            {
                "tag": "trojan-out",
                "protocol": "trojan",
                "settings": {
                    "servers": [
                        {
                            "address": host,
                            "port": port,
                            "password": password
                        }
                    ]
                },
                "streamSettings": {
                    "network": network,
                    "security": "tls",
                    "tlsSettings": {
                        "serverName": sni,
                        "allowInsecure": True
                    }
                }
            }
        ]
    }
    
    # Add WebSocket settings if needed
    if network == "ws":
        config["outbounds"][0]["streamSettings"]["wsSettings"] = {
            "path": ws_path,
            "headers": {
                "Host": ws_host
            }
        }
    
    return config, proxy_user, proxy_pass

# ─── Docker Management ────────────────────────────────────

def create_proxy_container(proxy_id: int):
    """Create and start a Docker container for a proxy"""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close()
        raise HTTPException(404, "Proxy not found")
    
    # Generate config with credentials
    proxy_data = dict(proxy)
    config, proxy_user, proxy_pass = generate_xray_config(proxy_data)
    
    # Write config file - use a directory per proxy to avoid volume conflicts
    config_dir_container = f"/app/xray-configs/proxy_{proxy_id}"
    config_dir_host = f"{XRAY_CONFIGS_HOST}/proxy_{proxy_id}"
    os.makedirs(config_dir_container, exist_ok=True)
    config_path = os.path.join(config_dir_container, "config.json")
    with open(config_path, "w") as f:
        json.dump(config, f, indent=2)
    
    # Container name
    container_name = f"proxy_{proxy['user_id']}_{proxy_id}"
    local_port = proxy["local_port"]
    
    # Create container - bind to 0.0.0.0 for external access
    cmd = [
        "docker", "run", "-d",
        "--name", container_name,
        "--restart", "unless-stopped",
        "--network", "trojan-panel_panel-net",
        "-p", f"0.0.0.0:{local_port}:1080",
        "-v", f"{config_dir_host}:/etc/xray:ro",
        XRAY_IMAGE
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode == 0:
            # Store credentials in database
            conn.execute("""
                UPDATE proxies SET status='RUNNING', container_name=?, 
                proxy_user=?, proxy_pass=? WHERE id=?
            """, (container_name, proxy_user, proxy_pass, proxy_id))
        else:
            conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
            print(f"Container error: {result.stderr}")
    except Exception as e:
        conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
        print(f"Container exception: {e}")
    
    conn.commit()
    conn.close()

def stop_proxy_container(proxy_id: int):
    """Stop a proxy container"""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy or not proxy["container_name"]:
        conn.close()
        return
    
    try:
        subprocess.run(["docker", "stop", proxy["container_name"]], 
                      capture_output=True, timeout=15)
        conn.execute("UPDATE proxies SET status='PAUSED' WHERE id=?", (proxy_id,))
    except:
        pass
    
    conn.commit()
    conn.close()

def start_proxy_container(proxy_id: int):
    """Start a proxy container"""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close()
        return
    
    if not proxy["container_name"]:
        # Container doesn't exist, create it
        conn.close()
        create_proxy_container(proxy_id)
        return
    
    try:
        result = subprocess.run(["docker", "start", proxy["container_name"]], 
                              capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            conn.execute("UPDATE proxies SET status='RUNNING' WHERE id=?", (proxy_id,))
        else:
            conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
    except:
        conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
    
    conn.commit()
    conn.close()

def delete_proxy_container(proxy_id: int):
    """Delete a proxy container and its config"""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close()
        return
    
    # Stop and remove container
    if proxy["container_name"]:
        try:
            subprocess.run(["docker", "rm", "-f", proxy["container_name"]], 
                          capture_output=True, timeout=15)
        except:
            pass
    
    # Remove config directory
    config_dir = f"/app/xray-configs/proxy_{proxy_id}"
    if os.path.exists(config_dir):
        import shutil
        shutil.rmtree(config_dir, ignore_errors=True)
    
    # Remove from database
    conn.execute("DELETE FROM proxies WHERE id=?", (proxy_id,))
    conn.commit()
    conn.close()

def sync_all_containers():
    """Sync container states with database on startup"""
    conn = get_db()
    proxies = conn.execute("SELECT * FROM proxies").fetchall()
    
    for proxy in proxies:
        if proxy["container_name"]:
            # Check if container exists and is running
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", proxy["container_name"]],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "true" in result.stdout:
                # Container exists and is running
                conn.execute("UPDATE proxies SET status='RUNNING' WHERE id=?", (proxy["id"],))
            else:
                # Container doesn't exist or not running
                conn.execute("UPDATE proxies SET status='PAUSED' WHERE id=?", (proxy["id"],))
        else:
            # No container name - mark as stopped
            conn.execute("UPDATE proxies SET status='STOPPED' WHERE id=?", (proxy["id"],))
    
    conn.commit()
    conn.close()

# ─── Proxy Tester ─────────────────────────────────────────

def test_proxy(proxy_id: int) -> dict:
    """Test a proxy by making a request through it"""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    if not proxy:
        return {"success": False, "error": "Proxy not found"}
    
    if proxy["status"] != "RUNNING":
        return {"success": False, "error": "Proxy not running"}
    
    local_port = proxy["local_port"]
    container_name = proxy["container_name"]
    start_time = time.time()
    
    try:
        # Use container name for Docker network access
        result = subprocess.run([
            "curl", "-x", f"socks5h://{container_name}:1080",
            "https://httpbin.org/ip", "--max-time", "10", "-s"
        ], capture_output=True, text=True, timeout=15)
        
        elapsed = int((time.time() - start_time) * 1000)
        
        if result.returncode == 0 and "origin" in result.stdout:
            ip = json.loads(result.stdout)["origin"]
            
            # Update database
            conn = get_db()
            conn.execute("""
                UPDATE proxies SET last_test_ip=?, last_test_ping=?, last_test_time=CURRENT_TIMESTAMP 
                WHERE id=?
            """, (ip, elapsed, proxy_id))
            conn.commit()
            conn.close()
            
            return {"success": True, "ip": ip, "ping": elapsed}
        else:
            return {"success": False, "error": result.stderr or "Connection failed"}
    except Exception as e:
        return {"success": False, "error": str(e)}

# ─── API Routes ───────────────────────────────────────────

@app.post("/api/auth/register")
async def register(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    existing = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Username already exists")
    
    pwd_hash = hash_password(password)
    cursor = conn.execute("INSERT INTO users (username, password_hash) VALUES (?, ?)", 
                         (username, pwd_hash))
    user_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    token = create_token(user_id, username, "user")
    resp = JSONResponse({"success": True, "user": {"id": user_id, "username": username}})
    resp.set_cookie("token", token, httponly=True, max_age=604800)
    return resp

@app.post("/api/auth/login")
async def login(username: str = Form(...), password: str = Form(...)):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    conn.close()
    
    if not user or user["password_hash"] != hash_password(password):
        raise HTTPException(401, "Invalid credentials")
    
    token = create_token(user["id"], user["username"], user["role"])
    resp = JSONResponse({"success": True, "user": {"id": user["id"], "username": user["username"], "role": user["role"]}})
    resp.set_cookie("token", token, httponly=True, max_age=604800)
    return resp

@app.get("/api/auth/me")
async def get_me(request: Request):
    user = require_user(request)
    return {"user": user}

@app.get("/api/auth/logout")
async def logout():
    resp = JSONResponse({"success": True})
    resp.delete_cookie("token")
    return resp

@app.get("/api/proxies")
async def list_proxies(request: Request):
    user = require_user(request)
    conn = get_db()
    
    if user.get("role") == "admin":
        proxies = conn.execute("""
            SELECT p.*, u.username as owner 
            FROM proxies p JOIN users u ON p.user_id = u.id 
            ORDER BY p.created_at DESC
        """).fetchall()
    else:
        proxies = conn.execute("""
            SELECT * FROM proxies WHERE user_id=? ORDER BY created_at DESC
        """, (user["user_id"],)).fetchall()
    
    conn.close()
    return {"proxies": [dict(p) for p in proxies]}

@app.post("/api/proxies")
async def create_proxy(request: Request):
    user = require_user(request)
    data = await request.json()
    
    raw_url = data.get("raw_url", "").strip()
    name = data.get("name", "").strip()
    
    # Parse URL if provided
    if raw_url:
        parsed = parse_trojan_url(raw_url)
        if not parsed["password"] or not parsed["host"]:
            raise HTTPException(400, "Invalid Trojan URL")
    else:
        # Manual input
        parsed = {
            "password": data.get("password", ""),
            "host": data.get("host", ""),
            "port": int(data.get("port", 443)),
            "sni": data.get("sni", ""),
            "network_type": data.get("network_type", "ws"),
            "ws_host": data.get("ws_host", ""),
            "ws_path": data.get("ws_path", "/")
        }
        if not parsed["password"] or not parsed["host"]:
            raise HTTPException(400, "Password and host required")
    
    if not parsed["sni"]:
        parsed["sni"] = parsed["host"]
    if not parsed["ws_host"]:
        parsed["ws_host"] = parsed["host"]
    if not name:
        name = f"{parsed['host']}:{parsed['port']}"
    
    # Allocate port
    local_port = find_available_port()
    
    conn = get_db()
    cursor = conn.execute("""
        INSERT INTO proxies (user_id, name, trojan_raw_url, trojan_password, trojan_host, 
                           trojan_port, trojan_sni, network_type, ws_host, ws_path, local_port, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'STOPPED')
    """, (user["user_id"], name, raw_url, parsed["password"], parsed["host"],
          parsed["port"], parsed["sni"], parsed["network_type"], 
          parsed["ws_host"], parsed["ws_path"], local_port))
    
    proxy_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    return {"success": True, "proxy_id": proxy_id, "local_port": local_port}

@app.post("/api/proxies/{proxy_id}/start")
async def start_proxy(request: Request, proxy_id: int):
    user = require_user(request)
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    if not proxy:
        raise HTTPException(404, "Proxy not found")
    if user.get("role") != "admin" and proxy["user_id"] != user["user_id"]:
        raise HTTPException(403, "Not your proxy")
    
    start_proxy_container(proxy_id)
    
    # Get updated proxy with credentials
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    # Build proxy format
    proxy_format = ""
    if proxy["proxy_user"] and proxy["proxy_pass"]:
        proxy_format = f"{VPS_IP}:{proxy['local_port']}:{proxy['proxy_user']}:{proxy['proxy_pass']}"
    else:
        proxy_format = f"{VPS_IP}:{proxy['local_port']}"
    
    return {
        "success": True, 
        "status": "RUNNING",
        "proxy_format": proxy_format,
        "proxy_url": f"socks5://{proxy['proxy_user']}:{proxy['proxy_pass']}@{VPS_IP}:{proxy['local_port']}"
    }

@app.post("/api/proxies/{proxy_id}/stop")
async def stop_proxy(request: Request, proxy_id: int):
    user = require_user(request)
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    if not proxy:
        raise HTTPException(404, "Proxy not found")
    if user.get("role") != "admin" and proxy["user_id"] != user["user_id"]:
        raise HTTPException(403, "Not your proxy")
    
    stop_proxy_container(proxy_id)
    return {"success": True, "status": "PAUSED"}

@app.delete("/api/proxies/{proxy_id}")
async def delete_proxy(request: Request, proxy_id: int):
    user = require_user(request)
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    if not proxy:
        raise HTTPException(404, "Proxy not found")
    if user.get("role") != "admin" and proxy["user_id"] != user["user_id"]:
        raise HTTPException(403, "Not your proxy")
    
    delete_proxy_container(proxy_id)
    return {"success": True}

@app.post("/api/proxies/{proxy_id}/test")
async def test_proxy_endpoint(request: Request, proxy_id: int):
    user = require_user(request)
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    if not proxy:
        raise HTTPException(404, "Proxy not found")
    if user.get("role") != "admin" and proxy["user_id"] != user["user_id"]:
        raise HTTPException(403, "Not your proxy")
    
    result = test_proxy(proxy_id)
    return result

@app.get("/api/proxies/{proxy_id}")
async def get_proxy(request: Request, proxy_id: int):
    user = require_user(request)
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    conn.close()
    
    if not proxy:
        raise HTTPException(404, "Proxy not found")
    if user.get("role") != "admin" and proxy["user_id"] != user["user_id"]:
        raise HTTPException(403, "Not your proxy")
    
    return {"proxy": dict(proxy)}

# ─── Admin Routes ─────────────────────────────────────────

@app.get("/api/admin/users")
async def list_users(request: Request):
    require_admin(request)
    conn = get_db()
    users = conn.execute("SELECT id, username, role, created_at FROM users").fetchall()
    conn.close()
    return {"users": [dict(u) for u in users]}

@app.delete("/api/admin/users/{user_id}")
async def delete_user(request: Request, user_id: int):
    require_admin(request)
    conn = get_db()
    
    # Delete all user's proxies first
    proxies = conn.execute("SELECT * FROM proxies WHERE user_id=?", (user_id,)).fetchall()
    for proxy in proxies:
        delete_proxy_container(proxy["id"])
    
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/stats")
async def get_stats(request: Request):
    user = require_user(request)
    conn = get_db()
    
    if user.get("role") == "admin":
        total_users = conn.execute("SELECT COUNT(*) as c FROM users").fetchone()["c"]
        total_proxies = conn.execute("SELECT COUNT(*) as c FROM proxies").fetchone()["c"]
        running_proxies = conn.execute("SELECT COUNT(*) as c FROM proxies WHERE status='RUNNING'").fetchone()["c"]
    else:
        total_users = 1
        total_proxies = conn.execute("SELECT COUNT(*) as c FROM proxies WHERE user_id=?", (user["user_id"],)).fetchone()["c"]
        running_proxies = conn.execute("SELECT COUNT(*) as c FROM proxies WHERE user_id=? AND status='RUNNING'", (user["user_id"],)).fetchone()["c"]
    
    conn.close()
    return {
        "total_users": total_users,
        "total_proxies": total_proxies,
        "running_proxies": running_proxies,
        "vps_ip": VPS_IP
    }

# ─── Frontend ─────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/register", response_class=HTMLResponse)
async def register_page(request: Request):
    return templates.TemplateResponse("register.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request):
    return templates.TemplateResponse("dashboard.html", {"request": request})

# ─── Startup ──────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    sync_all_containers()

# Mount static files and templates
templates = Jinja2Templates(directory="/app/frontend")
app.mount("/static", StaticFiles(directory="/app/frontend/static"), name="static")
