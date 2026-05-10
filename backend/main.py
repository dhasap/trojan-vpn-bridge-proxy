#!/usr/bin/env python3
"""
Trojan Proxy Panel - Backend API
Multi-user proxy management with Docker orchestration
"""

import json, os, hashlib, time, re, sqlite3, subprocess, socket, base64, secrets
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
VPS_IP = os.getenv("VPS_IP", "127.0.0.1")
PORT_RANGE_START = int(os.getenv("PORT_START", "20000"))
PORT_RANGE_END = int(os.getenv("PORT_END", "30000"))
XRAY_IMAGE = os.getenv("XRAY_IMAGE", "teddysun/xray:latest")
XRAY_CONFIGS_HOST = os.getenv("XRAY_CONFIGS_HOST", "/opt/vpn-bridge-proxy/xray-configs")
HOWDY_IMAGE = os.getenv("HOWDY_IMAGE", "howdy-bridge:latest")
PANEL_NETWORK = os.getenv("PANEL_NETWORK", "vpn-bridge-proxy_panel-net")
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
    # Lightweight schema migrations for existing installs.
    proxy_cols = [row[1] for row in conn.execute("PRAGMA table_info(proxies)").fetchall()]
    for col, ddl in {
        "proxy_user": "ALTER TABLE proxies ADD COLUMN proxy_user TEXT DEFAULT ''",
        "proxy_pass": "ALTER TABLE proxies ADD COLUMN proxy_pass TEXT DEFAULT ''",
        "source_type": "ALTER TABLE proxies ADD COLUMN source_type TEXT DEFAULT 'trojan'",
        "upstream_username": "ALTER TABLE proxies ADD COLUMN upstream_username TEXT DEFAULT ''",
        "upstream_password": "ALTER TABLE proxies ADD COLUMN upstream_password TEXT DEFAULT ''",
        "server_fingerprint": "ALTER TABLE proxies ADD COLUMN server_fingerprint TEXT DEFAULT ''",
    }.items():
        if col not in proxy_cols:
            conn.execute(ddl)

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
        
        # Split host:port?params and remove URI fragment (#name)
        # Trojan share links often append a display name after #. That fragment is
        # not part of query params; if left in params, parse_qs can put it into
        # sni/security fields and break TLS SNI.
        if "#" in rest:
            rest, _fragment = rest.split("#", 1)
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
        # Defensive cleanup: SNI must be a hostname, not a display label/comment.
        if not result["sni"] or result["sni"].startswith("#") or " " in result["sni"]:
            result["sni"] = result["host"]
        
    except Exception as e:
        print(f"Parse error: {e}")
    
    return result

def parse_howdy_url(url: str) -> dict:
    """Parse Howdy.ID share links: howdy://base64({server,sni,username,password,port})."""
    result = {
        "server": "",
        "port": 443,
        "sni": "",
        "username": "",
        "password": "",
        "protocol": "anyconnect",
    }
    if not url.startswith("howdy://"):
        return result
    try:
        raw = url.split("://", 1)[1].strip()
        raw += "=" * (-len(raw) % 4)
        data = json.loads(base64.urlsafe_b64decode(raw.encode()).decode())
        result["server"] = str(data.get("server") or data.get("host") or "").strip()
        result["port"] = int(data.get("port") or 443)
        result["sni"] = str(data.get("sni") or "").strip()
        result["username"] = str(data.get("username") or data.get("user") or "").strip()
        result["password"] = str(data.get("password") or data.get("pass") or "").strip()
    except Exception as e:
        print(f"Howdy parse error: {e}")
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

def build_xray_config(proxy_data: dict, proxy_user: str, proxy_pass: str, loglevel: str = "warning") -> dict:
    """Generate Xray-core config for a Trojan proxy using supplied client auth."""
    password = proxy_data["trojan_password"]
    host = proxy_data["trojan_host"]
    port = int(proxy_data.get("trojan_port") or 443)
    sni = proxy_data.get("trojan_sni") or host
    network = (proxy_data.get("network_type") or "ws").lower()
    ws_host = proxy_data.get("ws_host") or host
    ws_path = proxy_data.get("ws_path") or "/"

    stream_settings = {
        "network": network,
        "security": "tls",
        "tlsSettings": {"serverName": sni, "allowInsecure": True}
    }
    if network == "ws":
        stream_settings["wsSettings"] = {"path": ws_path, "headers": {"Host": ws_host}}
    elif network == "grpc":
        stream_settings["grpcSettings"] = {"serviceName": ws_path.lstrip("/") or "grpc"}

    return {
        "log": {"loglevel": loglevel},
        "inbounds": [
            {"tag": "socks-in", "port": 1080, "listen": "0.0.0.0", "protocol": "socks",
             "settings": {"auth": "password", "accounts": [{"user": proxy_user, "pass": proxy_pass}], "udp": True}},
            {"tag": "http-in", "port": 1081, "listen": "0.0.0.0", "protocol": "http",
             "settings": {"accounts": [{"user": proxy_user, "pass": proxy_pass}]}}
        ],
        "outbounds": [{
            "tag": "trojan-out", "protocol": "trojan",
            "settings": {"servers": [{"address": host, "port": port, "password": password}]},
            "streamSettings": stream_settings
        }]
    }

def generate_xray_config(proxy_data: dict) -> dict:
    """Generate Xray-core config for a Trojan proxy and fresh client auth."""
    proxy_user = proxy_data.get("proxy_user") or "proxy"
    proxy_pass = proxy_data.get("proxy_pass") or gen_pass()
    return build_xray_config(proxy_data, proxy_user, proxy_pass), proxy_user, proxy_pass

def _curl_probe(proxy_url: str, timeout: int = 8) -> dict:
    start_time = time.time()
    result = subprocess.run([
        "curl", "-x", proxy_url, "https://api.ipify.org?format=json",
        "--max-time", str(timeout), "-sS"
    ], capture_output=True, text=True, timeout=timeout + 4)
    elapsed = int((time.time() - start_time) * 1000)
    if result.returncode == 0:
        try:
            data = json.loads(result.stdout)
            if data.get("ip"):
                return {"success": True, "ip": data["ip"], "ping": elapsed}
        except Exception:
            pass
    return {"success": False, "error": (result.stderr.strip() or result.stdout.strip() or "connection failed"), "exit_code": result.returncode}

def smart_probe_trojan(parsed: dict) -> dict:
    """Try common Trojan transports before saving. Returns parsed fields updated to a working mode if found."""
    import uuid, shutil
    base = {
        "trojan_password": parsed["password"], "trojan_host": parsed["host"],
        "trojan_port": int(parsed.get("port") or 443), "trojan_sni": parsed.get("sni") or parsed["host"],
        "network_type": (parsed.get("network_type") or "ws").lower(),
        "ws_host": parsed.get("ws_host") or parsed["host"], "ws_path": parsed.get("ws_path") or "/"
    }
    candidates = []
    def add(label, network, sni=None, ws_host=None, ws_path=None):
        c = dict(base)
        c["network_type"] = network
        c["trojan_sni"] = sni if sni is not None else base["trojan_sni"]
        c["ws_host"] = ws_host if ws_host is not None else base["ws_host"]
        c["ws_path"] = ws_path if ws_path is not None else base["ws_path"]
        candidates.append((label, c))
    claimed = base["network_type"]
    if claimed == "ws":
        add("WS as imported", "ws")
        add("WS no Host header", "ws", ws_host="")
        add("Trojan TCP+TLS fallback", "tcp")
        add("Trojan TCP+TLS no SNI", "tcp", sni="")
    elif claimed == "tcp":
        add("TCP as imported", "tcp")
        add("TCP no SNI", "tcp", sni="")
        add("WS fallback", "ws")
    else:
        add(f"{claimed.upper()} as imported", claimed)
        add("WS fallback", "ws")
        add("TCP fallback", "tcp")

    probe_user = "proxy"
    probe_pass = gen_pass()
    attempts = []
    probe_id = uuid.uuid4().hex[:10]
    for idx, (label, proxy_data) in enumerate(candidates):
        cname = f"xray_probe_{probe_id}_{idx}"
        config_dir_container = f"/app/xray-configs/_probe_{probe_id}_{idx}"
        config_dir_host = f"{XRAY_CONFIGS_HOST}/_probe_{probe_id}_{idx}"
        os.makedirs(config_dir_container, exist_ok=True)
        config = build_xray_config(proxy_data, probe_user, probe_pass, loglevel="debug")
        # If ws_host is intentionally empty, omit Host header entirely.
        if proxy_data.get("network_type") == "ws" and not proxy_data.get("ws_host"):
            config["outbounds"][0]["streamSettings"]["wsSettings"].pop("headers", None)
        with open(os.path.join(config_dir_container, "config.json"), "w") as f:
            json.dump(config, f, indent=2)
        try:
            subprocess.run(["docker", "rm", "-f", cname], capture_output=True, timeout=10)
            run = subprocess.run(["docker", "run", "-d", "--name", cname, "--network", PANEL_NETWORK,
                                  "-v", f"{config_dir_host}:/etc/xray:ro", XRAY_IMAGE],
                                 capture_output=True, text=True, timeout=30)
            if run.returncode != 0:
                attempts.append({"label": label, "success": False, "error": run.stderr.strip()})
                continue
            time.sleep(1)
            result = _curl_probe(f"socks5h://{probe_user}:{probe_pass}@{cname}:1080")
            attempts.append({"label": label, "network": proxy_data.get("network_type"), **result})
            if result.get("success"):
                parsed["network_type"] = proxy_data["network_type"]
                parsed["sni"] = proxy_data.get("trojan_sni") or parsed["host"]
                parsed["ws_host"] = proxy_data.get("ws_host") or ""
                parsed["ws_path"] = proxy_data.get("ws_path") or ""
                return {"success": True, "parsed": parsed, "selected": label, "ip": result["ip"], "ping": result["ping"], "attempts": attempts}
        except Exception as e:
            attempts.append({"label": label, "success": False, "error": str(e)})
        finally:
            subprocess.run(["docker", "rm", "-f", cname], capture_output=True, timeout=10)
            shutil.rmtree(config_dir_container, ignore_errors=True)
    return {"success": False, "parsed": parsed, "attempts": attempts, "error": attempts[-1].get("error") if attempts else "No probe attempts"}

# ─── Howdy / OpenConnect Management ───────────────────────

def _docker_openconnect(args: list, password: str = "", timeout: int = 45) -> subprocess.CompletedProcess:
    """Run openconnect from the howdy-bridge image so the panel container stays lightweight."""
    cmd = [
        "docker", "run", "--rm", "-i", "--network", PANEL_NETWORK,
        "--entrypoint", "openconnect", HOWDY_IMAGE,
    ] + args
    return subprocess.run(cmd, input=password, capture_output=True, text=True, timeout=timeout)

def probe_howdy_fingerprint(server: str, port: int = 443, sni: str = "") -> str:
    """Return openconnect pin-sha256 fingerprint for an AnyConnect/ocserv server."""
    hostport = f"{server}:{int(port or 443)}"
    args = [
        "--protocol=anyconnect", "--authenticate",
        "--servercert", "pin-sha256:invalid", "--user", "probe",
        "--passwd-on-stdin", "--server", hostport
    ]
    try:
        result = _docker_openconnect(args, password="probe\n", timeout=35)
        text = result.stdout + "\n" + result.stderr
        m = re.search(r"pin-sha256:[A-Za-z0-9+/=]+", text)
        return m.group(0) if m else ""
    except Exception as e:
        print(f"Howdy fingerprint probe failed: {e}")
        return ""

def check_howdy_auth(parsed: dict) -> dict:
    """Authenticate only to confirm protocol and collect server evidence."""
    server = parsed.get("server") or parsed.get("host")
    port = int(parsed.get("port") or 443)
    user = parsed.get("username") or ""
    password = parsed.get("password") or ""
    fp = parsed.get("fingerprint") or probe_howdy_fingerprint(server, port, parsed.get("sni") or server)
    if not fp:
        return {"success": False, "error": "Could not read server certificate fingerprint"}
    args = [
        "--protocol=anyconnect", "--user", user,
        "--passwd-on-stdin", "--authenticate", "--server", f"{server}:{port}",
        "--servercert", fp
    ]
    try:
        result = _docker_openconnect(args, password=f"{password}\n", timeout=60)
        text = result.stdout + "\n" + result.stderr
        ok = result.returncode == 0 and ("COOKIE=" in text or "CONNECT_URL=" in text or "HOST=" in text)
        evidence = {}
        m = re.search(r"X-CSTP-Server-Name:\s*([^\r\n]+)", text)
        if m: evidence["server_name"] = m.group(1).strip()
        m = re.search(r"X-CSTP-Banner:\s*([^\r\n]+)", text)
        if m: evidence["banner"] = m.group(1).strip()
        m = re.search(r"HOST='([^']+)'", text)
        if m: evidence["host_ip"] = m.group(1).strip()
        return {"success": ok, "fingerprint": fp, "protocol": "anyconnect", "evidence": evidence,
                "error": "" if ok else (text.strip()[-800:] or "authentication failed")}
    except Exception as e:
        return {"success": False, "fingerprint": fp, "error": str(e)}

def create_howdy_proxy(proxy_id: int):
    """Create a public authenticated SOCKS5 Xray wrapper in front of a Howdy ocproxy container."""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close()
        raise HTTPException(404, "Proxy not found")
    proxy_data = dict(proxy)
    local_port = int(proxy_data["local_port"])
    bridge_name = f"howdy_bridge_{proxy_data['user_id']}_{proxy_id}"
    wrapper_name = f"proxy_{proxy_data['user_id']}_{proxy_id}"
    proxy_user = proxy_data.get("proxy_user") or "proxy"
    proxy_pass = proxy_data.get("proxy_pass") or gen_pass()
    upstream_host = proxy_data.get("trojan_host")
    upstream_port = int(proxy_data.get("trojan_port") or 443)
    upstream_user = proxy_data.get("upstream_username") or ""
    upstream_pass = proxy_data.get("upstream_password") or proxy_data.get("trojan_password") or ""
    fingerprint = proxy_data.get("server_fingerprint") or ""
    if not fingerprint:
        fingerprint = probe_howdy_fingerprint(upstream_host, upstream_port, proxy_data.get("trojan_sni") or upstream_host)

    # Remove stale containers first.
    subprocess.run(["docker", "rm", "-f", wrapper_name], capture_output=True, timeout=20)
    subprocess.run(["docker", "rm", "-f", bridge_name], capture_output=True, timeout=20)

    bridge_cmd = [
        "docker", "run", "-d", "--name", bridge_name, "--restart", "unless-stopped",
        "--network", PANEL_NETWORK,
        "-e", f"HOWDY_SERVER={upstream_host}:{upstream_port}",
        "-e", f"HOWDY_USER={upstream_user}",
        "-e", f"HOWDY_PASS={upstream_pass}",
        "-e", "HOWDY_SOCKS_PORT=1080",
    ]
    if fingerprint:
        bridge_cmd += ["-e", f"HOWDY_FINGERPRINT={fingerprint}"]
    bridge_cmd.append(HOWDY_IMAGE)

    try:
        run_bridge = subprocess.run(bridge_cmd, capture_output=True, text=True, timeout=40)
        if run_bridge.returncode != 0:
            conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
            conn.commit(); conn.close()
            print(f"Howdy bridge error: {run_bridge.stderr}")
            return

        # Wait until ocproxy listens inside the bridge container.
        ready = False
        for _ in range(25):
            probe = subprocess.run([
                "docker", "exec", bridge_name, "sh", "-c",
                "(ss -tln 2>/dev/null || netstat -tln 2>/dev/null || true) | grep -q ':1080'"
            ], capture_output=True, text=True, timeout=5)
            if probe.returncode == 0:
                ready = True
                break
            time.sleep(1)
        if not ready:
            logs = subprocess.run(["docker", "logs", bridge_name, "--tail", "80"], capture_output=True, text=True, timeout=10)
            subprocess.run(["docker", "rm", "-f", bridge_name], capture_output=True, timeout=20)
            conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
            conn.commit(); conn.close()
            print(f"Howdy bridge not ready: {logs.stdout[-1000:]} {logs.stderr[-1000:]}")
            return

        wrapper_config = {
            "log": {"loglevel": "warning"},
            "inbounds": [{
                "tag": "socks-in", "port": 1080, "listen": "0.0.0.0", "protocol": "socks",
                "settings": {"auth": "password", "accounts": [{"user": proxy_user, "pass": proxy_pass}], "udp": True}
            }],
            "outbounds": [{
                "tag": "to-howdy", "protocol": "socks",
                "settings": {"servers": [{"address": bridge_name, "port": 1080}]}
            }]
        }
        config_dir_container = f"/app/xray-configs/proxy_{proxy_id}"
        config_dir_host = f"{XRAY_CONFIGS_HOST}/proxy_{proxy_id}"
        os.makedirs(config_dir_container, exist_ok=True)
        with open(os.path.join(config_dir_container, "config.json"), "w") as f:
            json.dump(wrapper_config, f, indent=2)

        wrapper_cmd = [
            "docker", "run", "-d", "--name", wrapper_name, "--restart", "unless-stopped",
            "--network", PANEL_NETWORK,
            "-p", f"0.0.0.0:{local_port}:1080",
            "-v", f"{config_dir_host}:/etc/xray:ro",
            XRAY_IMAGE
        ]
        run_wrapper = subprocess.run(wrapper_cmd, capture_output=True, text=True, timeout=30)
        if run_wrapper.returncode == 0:
            conn.execute("""
                UPDATE proxies SET status='RUNNING', container_name=?, proxy_user=?, proxy_pass=?, server_fingerprint=?
                WHERE id=?
            """, (wrapper_name, proxy_user, proxy_pass, fingerprint, proxy_id))
        else:
            subprocess.run(["docker", "rm", "-f", bridge_name], capture_output=True, timeout=20)
            conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
            print(f"Howdy wrapper error: {run_wrapper.stderr}")
    except Exception as e:
        subprocess.run(["docker", "rm", "-f", wrapper_name], capture_output=True, timeout=20)
        subprocess.run(["docker", "rm", "-f", bridge_name], capture_output=True, timeout=20)
        conn.execute("UPDATE proxies SET status='ERROR' WHERE id=?", (proxy_id,))
        print(f"Howdy create exception: {e}")
    conn.commit()
    conn.close()

def stop_howdy_proxy(proxy_id: int):
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close(); return
    bridge_name = f"howdy_bridge_{proxy['user_id']}_{proxy_id}"
    wrapper_name = proxy["container_name"] or f"proxy_{proxy['user_id']}_{proxy_id}"
    subprocess.run(["docker", "stop", wrapper_name], capture_output=True, timeout=15)
    subprocess.run(["docker", "stop", bridge_name], capture_output=True, timeout=15)
    conn.execute("UPDATE proxies SET status='PAUSED' WHERE id=?", (proxy_id,))
    conn.commit(); conn.close()

def start_howdy_proxy(proxy_id: int):
    # Recreate both containers to refresh AnyConnect login cookies cleanly.
    create_howdy_proxy(proxy_id)

def delete_howdy_proxy(proxy_id: int):
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close(); return
    bridge_name = f"howdy_bridge_{proxy['user_id']}_{proxy_id}"
    wrapper_name = proxy["container_name"] or f"proxy_{proxy['user_id']}_{proxy_id}"
    subprocess.run(["docker", "rm", "-f", wrapper_name], capture_output=True, timeout=20)
    subprocess.run(["docker", "rm", "-f", bridge_name], capture_output=True, timeout=20)
    config_dir = f"/app/xray-configs/proxy_{proxy_id}"
    if os.path.exists(config_dir):
        import shutil
        shutil.rmtree(config_dir, ignore_errors=True)
    conn.execute("DELETE FROM proxies WHERE id=?", (proxy_id,))
    conn.commit(); conn.close()

# ─── Docker Management ────────────────────────────────────

def create_proxy_container(proxy_id: int):
    """Create and start a Docker container for a proxy"""
    conn = get_db()
    proxy = conn.execute("SELECT * FROM proxies WHERE id=?", (proxy_id,)).fetchone()
    if not proxy:
        conn.close()
        raise HTTPException(404, "Proxy not found")
    
    if (proxy["source_type"] or "trojan") == "howdy":
        conn.close()
        create_howdy_proxy(proxy_id)
        return

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
        "--network", PANEL_NETWORK,
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
    if not proxy:
        conn.close()
        return
    if (proxy["source_type"] or "trojan") == "howdy":
        conn.close()
        stop_howdy_proxy(proxy_id)
        return
    if not proxy["container_name"]:
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
    if (proxy["source_type"] or "trojan") == "howdy":
        conn.close()
        start_howdy_proxy(proxy_id)
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
    if (proxy["source_type"] or "trojan") == "howdy":
        conn.close()
        delete_howdy_proxy(proxy_id)
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
        source_type = proxy["source_type"] or "trojan"
        if source_type == "howdy":
            bridge_name = f"howdy_bridge_{proxy['user_id']}_{proxy['id']}"
            wrapper_name = proxy["container_name"] or f"proxy_{proxy['user_id']}_{proxy['id']}"
            wrapper = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", wrapper_name], capture_output=True, text=True, timeout=5)
            bridge = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", bridge_name], capture_output=True, text=True, timeout=5)
            if wrapper.returncode == 0 and "true" in wrapper.stdout and bridge.returncode == 0 and "true" in bridge.stdout:
                conn.execute("UPDATE proxies SET status='RUNNING', container_name=? WHERE id=?", (wrapper_name, proxy["id"]))
            else:
                conn.execute("UPDATE proxies SET status='PAUSED' WHERE id=?", (proxy["id"],))
        elif proxy["container_name"]:
            # Check if container exists and is running
            result = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.Running}}", proxy["container_name"]],
                capture_output=True, text=True, timeout=5
            )
            if result.returncode == 0 and "true" in result.stdout:
                conn.execute("UPDATE proxies SET status='RUNNING' WHERE id=?", (proxy["id"],))
            else:
                conn.execute("UPDATE proxies SET status='PAUSED' WHERE id=?", (proxy["id"],))
        else:
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
        # Use container name with auth for Docker network access
        proxy_user = proxy["proxy_user"] or "proxy"
        proxy_pass = proxy["proxy_pass"] or ""
        source_type = proxy["source_type"] or "trojan"
        
        if proxy_pass:
            proxy_url = f"socks5h://{proxy_user}:{proxy_pass}@{container_name}:1080"
        else:
            proxy_url = f"socks5h://{container_name}:1080"
        
        result = subprocess.run([
            "curl", "-x", proxy_url,
            "https://httpbin.org/ip", "--max-time", "15", "-s"
        ], capture_output=True, text=True, timeout=20)
        
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
            error = result.stderr.strip() or result.stdout.strip() or "Connection failed"
            conn = get_db()
            conn.execute("""
                UPDATE proxies SET last_test_ip='', last_test_ping=0, last_test_time=CURRENT_TIMESTAMP
                WHERE id=?
            """, (proxy_id,))
            conn.commit()
            conn.close()
            return {"success": False, "error": error, "exit_code": result.returncode}
    except Exception as e:
        conn = get_db()
        conn.execute("""
            UPDATE proxies SET last_test_ip='', last_test_ping=0, last_test_time=CURRENT_TIMESTAMP
            WHERE id=?
        """, (proxy_id,))
        conn.commit()
        conn.close()
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
    
    source_type = (data.get("source_type") or "").strip().lower()
    if raw_url.startswith("howdy://"):
        source_type = "howdy"
    elif not source_type:
        source_type = "trojan"

    # Parse URL if provided
    howdy_probe = None
    if source_type == "howdy":
        if raw_url:
            h = parse_howdy_url(raw_url)
        else:
            h = {
                "server": data.get("server") or data.get("host") or "",
                "port": int(data.get("port", 443)),
                "sni": data.get("sni", ""),
                "username": data.get("username", ""),
                "password": data.get("password", ""),
            }
        if not h.get("server") or not h.get("username") or not h.get("password"):
            raise HTTPException(400, "Invalid Howdy URL/config")
        parsed = {
            "password": h["password"],
            "host": h["server"],
            "port": int(h.get("port") or 443),
            "sni": h.get("sni") or h["server"],
            "network_type": "anyconnect",
            "ws_host": "",
            "ws_path": "/",
            "upstream_username": h["username"],
            "upstream_password": h["password"],
        }
        if data.get("smart", True):
            howdy_probe = check_howdy_auth({**h, "fingerprint": data.get("server_fingerprint", "")})
            if howdy_probe.get("fingerprint"):
                parsed["server_fingerprint"] = howdy_probe["fingerprint"]
    elif raw_url:
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
    if not parsed["ws_host"] and (parsed.get("network_type") or "ws") == "ws":
        parsed["ws_host"] = parsed["host"]

    # Smart import: probe common Trojan transport variants before saving.
    # This catches links that claim WS but actually work as TCP+TLS, bad Host headers,
    # and dead/invalid upstream accounts. Set smart=false in JSON to skip.
    smart_result = None
    if source_type == "trojan" and data.get("smart", True):
        smart_result = smart_probe_trojan(parsed.copy())
        if smart_result.get("success"):
            parsed = smart_result["parsed"]

    if not name:
        if source_type == "howdy":
            name = f"Howdy {parsed['host']}:{parsed['port']}"
        else:
            suffix = f" {parsed.get('network_type', 'ws').upper()}" if smart_result and smart_result.get("success") else ""
            name = f"{parsed['host']}:{parsed['port']}{suffix}"
    
    # Allocate port
    local_port = find_available_port()
    
    conn = get_db()
    cursor = conn.execute("""
        INSERT INTO proxies (user_id, name, trojan_raw_url, trojan_password, trojan_host, 
                           trojan_port, trojan_sni, network_type, ws_host, ws_path, local_port, status,
                           source_type, upstream_username, upstream_password, server_fingerprint)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'STOPPED', ?, ?, ?, ?)
    """, (user["user_id"], name, raw_url, parsed["password"], parsed["host"],
          parsed["port"], parsed["sni"], parsed["network_type"], 
          parsed["ws_host"], parsed["ws_path"], local_port, source_type,
          parsed.get("upstream_username", ""), parsed.get("upstream_password", ""), parsed.get("server_fingerprint", "")))
    
    proxy_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    response = {"success": True, "proxy_id": proxy_id, "local_port": local_port}
    if smart_result:
        response["smart"] = {
            "success": smart_result.get("success", False),
            "selected": smart_result.get("selected"),
            "ip": smart_result.get("ip"),
            "ping": smart_result.get("ping"),
            "error": smart_result.get("error"),
            "attempts": smart_result.get("attempts", [])
        }
    if howdy_probe:
        response["howdy"] = {
            "success": howdy_probe.get("success", False),
            "protocol": howdy_probe.get("protocol", "anyconnect"),
            "fingerprint": howdy_probe.get("fingerprint"),
            "evidence": howdy_probe.get("evidence", {}),
            "error": howdy_probe.get("error"),
        }
    return response

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
        "proxy_url": f"socks5h://{proxy['proxy_user']}:{proxy['proxy_pass']}@{VPS_IP}:{proxy['local_port']}"
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

@app.get("/proxy-test", response_class=HTMLResponse)
async def proxy_test_page(request: Request):
    return templates.TemplateResponse("proxy-test.html", {"request": request})

# ─── Startup ──────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    sync_all_containers()

# Mount static files and templates
templates = Jinja2Templates(directory="/app/frontend")
app.mount("/static", StaticFiles(directory="/app/frontend/static"), name="static")


