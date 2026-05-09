// ─── State ────────────────────────────────────────────────

let currentUser = null;
let proxies = [];
const VPS_IP = "8.222.230.139";

// ─── Init ─────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
    await checkAuth();
    await loadStats();
    await loadProxies();
});

// ─── Auth ─────────────────────────────────────────────────

async function checkAuth() {
    try {
        const res = await fetch('/api/auth/me', { credentials: 'same-origin' });
        if (!res.ok) throw new Error('Not authenticated');
        const data = await res.json();
        currentUser = data.user;
    } catch (err) {
        window.location.href = '/login';
    }
}

async function logout() {
    await fetch('/api/auth/logout', { credentials: 'same-origin' });
    window.location.href = '/login';
}

// ─── Stats ────────────────────────────────────────────────

async function loadStats() {
    try {
        const res = await fetch('/api/stats', { credentials: 'same-origin' });
        const data = await res.json();
        document.getElementById('statProxies').textContent = data.total_proxies;
        document.getElementById('statRunning').textContent = data.running_proxies;
        document.getElementById('statIP').textContent = data.vps_ip;
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

// ─── Proxies ──────────────────────────────────────────────

async function loadProxies() {
    try {
        const res = await fetch('/api/proxies', { credentials: 'same-origin' });
        const data = await res.json();
        proxies = data.proxies;
        renderProxies();
    } catch (err) {
        console.error('Failed to load proxies:', err);
    }
}

function renderProxies() {
    const list = document.getElementById('proxyList');
    
    if (proxies.length === 0) {
        list.innerHTML = `
            <div class="empty">
                <div class="icon">📦</div>
                <p>No proxies yet. Add your first proxy!</p>
            </div>
        `;
        return;
    }
    
    list.innerHTML = proxies.map(p => `
        <div class="proxy-card">
            <div class="proxy-info">
                <div class="proxy-name">
                    ${escapeHtml(p.name)}
                    <span class="proxy-status status-${p.status}">${p.status}</span>
                </div>
                <div class="proxy-details">
                    ${escapeHtml(p.trojan_host)}:${p.trojan_port} | ${p.network_type.toUpperCase()}
                </div>
                ${p.proxy_user && p.proxy_pass ? `
                    <div class="proxy-format">
                        <strong>Proxy Format:</strong>
                        <div class="proxy-box" onclick="cp('${VPS_IP}:${p.local_port}:${p.proxy_user}:${p.proxy_pass}', this)">
                            <span>${VPS_IP}:${p.local_port}:${p.proxy_user}:${p.proxy_pass}</span>
                            <span class="ch">Copy</span>
                        </div>
                        <div class="proxy-url">
                            <strong>SOCKS5 URL:</strong>
                            <div class="proxy-box" onclick="cp('socks5://${p.proxy_user}:${p.proxy_pass}@${VPS_IP}:${p.local_port}', this)">
                                <span>socks5://${p.proxy_user}:${p.proxy_pass}@${VPS_IP}:${p.local_port}</span>
                                <span class="ch">Copy</span>
                            </div>
                        </div>
                    </div>
                ` : `
                    <div class="proxy-port">
                        Port: ${p.local_port > 0 ? VPS_IP + ':' + p.local_port : 'Not allocated'}
                    </div>
                `}
                ${p.last_test_ip ? `
                    <div class="proxy-test">
                        Last test: IP ${p.last_test_ip} | Ping ${p.last_test_ping}ms
                    </div>
                ` : ''}
                ${p.status === 'RUNNING' && p.proxy_user && p.proxy_pass ? `
                    <div class="proxy-test-url">
                        <strong>Test in Browser:</strong>
                        <div class="proxy-box" onclick="window.open('/proxy-test?host=${VPS_IP}&port=${p.local_port}&user=${p.proxy_user}&pass=${p.proxy_pass}', '_blank')">
                            <span>Open Proxy Test Page</span>
                        </div>
                        <div style="margin-top:0.3rem;font-size:0.75rem;color:var(--muted)">
                            Set SOCKS5 proxy in browser: ${VPS_IP}:${p.local_port}<br>
                            User: ${p.proxy_user} | Pass: ${p.proxy_pass}
                        </div>
                    </div>
                ` : ''}
            </div>
            <div class="proxy-actions">
                ${p.status === 'STOPPED' || p.status === 'PAUSED' ? `
                    <button class="btn btn-success btn-sm" onclick="startProxy(${p.id})">Start</button>
                ` : `
                    <button class="btn btn-warn btn-sm" onclick="stopProxy(${p.id})">Stop</button>
                `}
                <button class="btn btn-primary btn-sm" onclick="testProxy(${p.id})">Test</button>
                <button class="btn btn-danger btn-sm" onclick="deleteProxy(${p.id})">Delete</button>
            </div>
        </div>
    `).join('');
}

// ─── Proxy Actions ────────────────────────────────────────

async function addFromUrl() {
    const url = document.getElementById('trojanUrl').value.trim();
    const name = document.getElementById('urlName').value.trim();
    
    if (!url) {
        showToast('Please enter a Trojan URL', 'error');
        return;
    }
    
    try {
        const res = await fetch('/api/proxies', { credentials: 'same-origin', 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_url: url, name: name })
        });
        
        const data = await res.json();
        if (data.success) {
            showToast('Proxy added! Port: ' + data.local_port, 'success');
            document.getElementById('trojanUrl').value = '';
            document.getElementById('urlName').value = '';
            showSection('proxies');
            await loadProxies();
            await loadStats();
        } else {
            showToast(data.detail || 'Failed to add proxy', 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    }
}

async function addManual() {
    const password = document.getElementById('manualPassword').value.trim();
    const host = document.getElementById('manualHost').value.trim();
    const port = document.getElementById('manualPort').value;
    const sni = document.getElementById('manualSni').value.trim();
    const network = document.getElementById('manualNetwork').value;
    const path = document.getElementById('manualPath').value.trim();
    const name = document.getElementById('manualName').value.trim();
    
    if (!password || !host) {
        showToast('Password and host are required', 'error');
        return;
    }
    
    try {
        const res = await fetch('/api/proxies', { credentials: 'same-origin', 
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                password, host, port: parseInt(port), sni,
                network_type: network, ws_path: path, name
            })
        });
        
        const data = await res.json();
        if (data.success) {
            showToast('Proxy added! Port: ' + data.local_port, 'success');
            showSection('proxies');
            await loadProxies();
            await loadStats();
        } else {
            showToast(data.detail || 'Failed to add proxy', 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    }
}

async function startProxy(id) {
    try {
        const res = await fetch(`/api/proxies/${id}/start`, { method: 'POST', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) {
            showToast('Proxy started! Format: ' + data.proxy_format, 'success');
            await loadProxies();
            await loadStats();
        } else {
            showToast(data.detail || 'Failed to start', 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    }
}

async function stopProxy(id) {
    try {
        const res = await fetch(`/api/proxies/${id}/stop`, { method: 'POST', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) {
            showToast('Proxy stopped', 'success');
            await loadProxies();
            await loadStats();
        } else {
            showToast(data.detail || 'Failed to stop', 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    }
}

async function deleteProxy(id) {
    if (!confirm('Are you sure you want to delete this proxy?')) return;
    
    try {
        const res = await fetch(`/api/proxies/${id}`, { method: 'DELETE', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) {
            showToast('Proxy deleted', 'success');
            await loadProxies();
            await loadStats();
        } else {
            showToast(data.detail || 'Failed to delete', 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    }
}

async function testProxy(id) {
    showToast('Testing...', 'success');
    
    try {
        const res = await fetch(`/api/proxies/${id}/test`, { method: 'POST', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) {
            showToast(`OK! IP: ${data.ip} | Ping: ${data.ping}ms`, 'success');
            await loadProxies();
        } else {
            showToast(`Test failed: ${data.error}`, 'error');
        }
    } catch (err) {
        showToast('Network error', 'error');
    }
}

// ─── UI Helpers ───────────────────────────────────────────

function showSection(name) {
    document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    
    document.getElementById('section-' + name).style.display = 'block';
    document.getElementById('nav-' + name)?.classList.add('active');
}

function showTab(name) {
    document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    
    document.getElementById('tab-' + name).style.display = 'block';
    event.target.classList.add('active');
}

function showToast(msg, type) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = 'toast ' + type;
    setTimeout(() => {
        toast.className = 'toast';
    }, 3000);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
