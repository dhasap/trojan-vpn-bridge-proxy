// State
let currentUser = null;
let proxies = [];
let stats = {};
const VPS_IP = window.location.hostname || "127.0.0.1";

document.addEventListener('DOMContentLoaded', async () => {
    await checkAuth();
    await loadAll();
});

async function loadAll() {
    await Promise.all([loadStats(), loadProxies()]);
    renderHealthSummary();
}

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

async function loadStats() {
    try {
        const res = await fetch('/api/stats', { credentials: 'same-origin' });
        stats = await res.json();
        document.getElementById('statProxies').textContent = stats.total_proxies ?? 0;
        document.getElementById('statRunning').textContent = stats.running_proxies ?? 0;
        document.getElementById('statIP').textContent = stats.vps_ip || VPS_IP;
    } catch (err) {
        console.error('Failed to load stats:', err);
    }
}

async function loadProxies() {
    try {
        const res = await fetch('/api/proxies', { credentials: 'same-origin' });
        const data = await res.json();
        proxies = data.proxies || [];
        renderProxies();
    } catch (err) {
        console.error('Failed to load proxies:', err);
        document.getElementById('proxyList').innerHTML = '<div class="empty">Failed to load proxies</div>';
    }
}

function renderHealthSummary() {
    const el = document.getElementById('statHealth');
    if (!el) return;
    const tested = proxies.filter(p => p.last_test_ip);
    const running = proxies.filter(p => p.status === 'RUNNING');
    if (!proxies.length) el.textContent = 'No data';
    else if (!tested.length) el.textContent = 'Untested';
    else el.textContent = `${tested.length}/${running.length || proxies.length} tested`;
}

function renderProxies() {
    const list = document.getElementById('proxyList');
    const filter = (document.getElementById('proxyFilter')?.value || '').toLowerCase().trim();
    const shown = proxies.filter(p => {
        const text = `${p.name} ${p.source_type || 'trojan'} ${p.trojan_host} ${p.upstream_username || ''} ${p.local_port} ${p.status} ${p.last_test_ip || ''}`.toLowerCase();
        return !filter || text.includes(filter);
    });

    if (shown.length === 0) {
        list.innerHTML = `
            <div class="empty">
                <div class="icon">[]</div>
                <p>${proxies.length ? 'No proxies match the filter.' : 'No proxies yet. Add your first Trojan URL.'}</p>
            </div>`;
        renderHealthSummary();
        return;
    }

    list.innerHTML = shown.map(p => proxyCard(p)).join('');
    renderHealthSummary();
}

function proxyCard(p) {
    const sourceType = (p.source_type || 'trojan').toLowerCase();
    const isHowdy = sourceType === 'howdy';
    const host = p.trojan_host || '-';
    const sni = p.trojan_sni || host;
    const path = p.ws_path || '/';
    const wsHost = p.ws_host || host;
    const protocolLabel = isHowdy ? 'HOWDY / ANYCONNECT' : (p.network_type || 'ws').toUpperCase();
    const sourceLabel = isHowdy ? 'Howdy VPN' : 'Trojan';
    const detailText = isHowdy ? `${host}:${p.trojan_port || 443} AnyConnect -> ${VPS_IP}:${p.local_port}` : `${host}:${p.trojan_port || 443} -> ${VPS_IP}:${p.local_port}`;
    const format = p.proxy_user && p.proxy_pass ? `${VPS_IP}:${p.local_port}:${p.proxy_user}:${p.proxy_pass}` : `${VPS_IP}:${p.local_port}`;
    const socksUrl = p.proxy_user && p.proxy_pass ? `socks5h://${p.proxy_user}:${p.proxy_pass}@${VPS_IP}:${p.local_port}` : `socks5h://${VPS_IP}:${p.local_port}`;
    const curlCmd = `curl -x ${socksUrl} https://httpbin.org/ip`;
    const health = healthFor(p);

    const metaGrid = isHowdy ? `
                <div class="meta"><small>Protocol</small><span>${escapeHtml(protocolLabel)}</span></div>
                <div class="meta"><small>Server</small><span title="${escapeAttr(host)}:${p.trojan_port || 443}">${escapeHtml(host)}:${p.trojan_port || 443}</span></div>
                <div class="meta"><small>Username</small><span title="${escapeAttr(p.upstream_username || '-')}">${escapeHtml(p.upstream_username || '-')}</span></div>
                <div class="meta"><small>SNI</small><span title="${escapeAttr(sni)}">${escapeHtml(sni)}</span></div>` : `
                <div class="meta"><small>Network</small><span>${escapeHtml(protocolLabel)}</span></div>
                <div class="meta"><small>${(p.network_type || 'ws') === 'ws' ? 'WS Path' : 'Service/Path'}</small><span title="${escapeAttr(path || '-')}">${escapeHtml(path || '-')}</span></div>
                <div class="meta"><small>SNI</small><span title="${escapeAttr(sni)}">${escapeHtml(sni)}</span></div>
                <div class="meta"><small>Host Header</small><span title="${escapeAttr(wsHost || '-')}">${escapeHtml(wsHost || '-')}</span></div>`;

    return `
        <article class="proxy-card ${isHowdy ? 'howdy-card' : ''}">
            <div class="proxy-top">
                <div>
                    <div class="proxy-name">${escapeHtml(p.name || host)} <span class="source-badge ${isHowdy ? 'source-howdy' : 'source-trojan'}">${sourceLabel}</span></div>
                    <div class="proxy-details">${escapeHtml(detailText)}</div>
                </div>
                <span class="proxy-status status-${escapeAttr(p.status)}">${escapeHtml(p.status)}</span>
            </div>

            <div class="health-line">
                <span class="health-pill ${health.className}">${health.label}</span>
                <span>${health.note}</span>
            </div>

            <div class="proxy-grid">${metaGrid}
            </div>

            <div class="proxy-format">
                <strong>Copy format</strong>
                <div class="proxy-box" onclick="cp('${escapeJs(format)}', this)">
                    <span>${escapeHtml(format)}</span><span class="ch">Copy</span>
                </div>
                <div class="proxy-url">
                    <strong>SOCKS5H URL</strong>
                    <div class="proxy-box" onclick="cp('${escapeJs(socksUrl)}', this)">
                        <span>${escapeHtml(socksUrl)}</span><span class="ch">Copy</span>
                    </div>
                </div>
                <div class="proxy-url">
                    <strong>Terminal test command</strong>
                    <div class="proxy-box" onclick="cp('${escapeJs(curlCmd)}', this)">
                        <span>${escapeHtml(curlCmd)}</span><span class="ch">Copy</span>
                    </div>
                </div>
            </div>

            ${p.last_test_ip ? `<div class="proxy-test">Last test: exit IP ${escapeHtml(p.last_test_ip)} | ${p.last_test_ping || '-'}ms | ${escapeHtml(p.last_test_time || '')}</div>` : ''}

            ${p.status === 'RUNNING' && p.proxy_user && p.proxy_pass ? `
                <div class="proxy-test-url">
                    <strong>Browser helper</strong>
                    <div class="proxy-box" onclick="window.open('/proxy-test?host=${encodeURIComponent(VPS_IP)}&port=${encodeURIComponent(p.local_port)}&user=${encodeURIComponent(p.proxy_user)}&pass=${encodeURIComponent(p.proxy_pass)}', '_blank')">
                        <span>Open proxy test helper</span><span class="ch">Open</span>
                    </div>
                </div>` : ''}

            <div class="proxy-actions">
                ${p.status === 'STOPPED' || p.status === 'PAUSED' ? `<button class="btn btn-success btn-sm" onclick="startProxy(${p.id})">Start</button>` : `<button class="btn btn-warn btn-sm" onclick="stopProxy(${p.id})">Stop</button>`}
                <button class="btn btn-primary btn-sm" onclick="testProxy(${p.id})">Test</button>
                <button class="btn btn-secondary btn-sm" onclick="cp('${escapeJs(curlCmd)}', this)">Copy Test</button>
                <button class="btn btn-danger btn-sm" onclick="deleteProxy(${p.id})">Delete</button>
            </div>
        </article>`;
}

function healthFor(p) {
    const isHowdy = (p.source_type || 'trojan').toLowerCase() === 'howdy';
    if (p.status === 'ERROR') return { label: 'Error', className: 'health-bad', note: 'Container or config error.' };
    if (p.status !== 'RUNNING') return { label: 'Paused', className: 'health-warn', note: 'Start it before testing.' };
    if (!p.proxy_user || !p.proxy_pass) return { label: 'No auth', className: 'health-warn', note: 'Proxy credentials missing.' };
    if (!p.last_test_ip) return { label: 'Untested', className: 'health-warn', note: 'Click Test to verify outbound IP.' };
    if (!isHowdy && ((p.trojan_sni || '').startsWith('#') || (p.trojan_sni || '').includes(' '))) return { label: 'Bad SNI', className: 'health-bad', note: 'SNI looks like a comment, not hostname.' };
    return { label: 'Tested', className: 'health-ok', note: `${isHowdy ? 'Howdy exit' : 'Outbound IP'} ${p.last_test_ip}.` };
}

async function addFromUrl() {
    const url = document.getElementById('trojanUrl').value.trim();
    const name = document.getElementById('urlName').value.trim();
    const smart = document.getElementById('smartUrl')?.checked ?? true;
    if (!url) return showToast('Please enter a Trojan or Howdy URL', 'error');
    try {
        showToast(smart ? 'Smart probing upstream...' : 'Adding proxy...', 'success');
        const res = await fetch('/api/proxies', {
            credentials: 'same-origin', method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ raw_url: url, name, smart })
        });
        const data = await res.json();
        if (data.success) {
            showToast(smartSummary(data), (data.smart && data.smart.success === false) || (data.howdy && data.howdy.success === false) ? 'error' : 'success');
            document.getElementById('trojanUrl').value = '';
            document.getElementById('urlName').value = '';
            showSection('proxies');
            await loadAll();
        } else showToast(data.detail || 'Failed to add proxy', 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

async function addManual() {
    const password = document.getElementById('manualPassword').value.trim();
    const host = document.getElementById('manualHost').value.trim();
    const port = document.getElementById('manualPort').value;
    const sni = document.getElementById('manualSni').value.trim();
    const network = document.getElementById('manualNetwork').value;
    const path = document.getElementById('manualPath').value.trim();
    const name = document.getElementById('manualName').value.trim();
    const smart = document.getElementById('smartManual')?.checked ?? true;
    if (!password || !host) return showToast('Password and host are required', 'error');
    try {
        showToast(smart ? 'Smart probing Trojan upstream...' : 'Adding proxy...', 'success');
        const res = await fetch('/api/proxies', {
            credentials: 'same-origin', method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password, host, port: parseInt(port, 10), sni, network_type: network, ws_path: path, name, smart })
        });
        const data = await res.json();
        if (data.success) {
            showToast(smartSummary(data), data.smart && data.smart.success === false ? 'error' : 'success');
            showSection('proxies');
            await loadAll();
        } else showToast(data.detail || 'Failed to add proxy', 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

async function addHowdyManual() {
    const server = document.getElementById('howdyServer').value.trim();
    const port = parseInt(document.getElementById('howdyPort').value || '443', 10);
    const username = document.getElementById('howdyUsername').value.trim();
    const password = document.getElementById('howdyPassword').value.trim();
    const sni = document.getElementById('howdySni').value.trim();
    const name = document.getElementById('howdyName').value.trim();
    const smart = document.getElementById('smartHowdy')?.checked ?? true;
    if (!server || !username || !password) return showToast('Server, username, and password are required', 'error');
    try {
        showToast(smart ? 'Verifying Howdy/OpenConnect login...' : 'Adding Howdy proxy...', 'success');
        const res = await fetch('/api/proxies', {
            credentials: 'same-origin', method: 'POST', headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ source_type: 'howdy', server, port, username, password, sni, name, smart })
        });
        const data = await res.json();
        if (data.success) {
            showToast(smartSummary(data), data.howdy && data.howdy.success === false ? 'error' : 'success');
            showSection('proxies');
            await loadAll();
        } else showToast(data.detail || 'Failed to add Howdy proxy', 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

function smartSummary(data) {
    if (data.howdy) {
        if (data.howdy.success) return `Howdy add OK: ${data.howdy.protocol || 'AnyConnect'} | port ${data.local_port}`;
        return `Howdy added but login probe failed on port ${data.local_port}: ${data.howdy.error || 'check account'}`;
    }
    if (!data.smart) return 'Proxy added. Port: ' + data.local_port;
    if (data.smart.success) {
        return `Smart add OK: ${data.smart.selected || 'working mode'} | ${data.smart.ip || 'IP unknown'} | port ${data.local_port}`;
    }
    const tried = (data.smart.attempts || []).map(a => a.label).filter(Boolean).join(', ');
    return `Added but upstream failed smart test on port ${data.local_port}. Tried: ${tried || 'variants'}`;
}

async function startProxy(id) {
    try {
        const res = await fetch(`/api/proxies/${id}/start`, { method: 'POST', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) { showToast('Proxy started: ' + data.proxy_format, 'success'); await loadAll(); }
        else showToast(data.detail || 'Failed to start', 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

async function stopProxy(id) {
    try {
        const res = await fetch(`/api/proxies/${id}/stop`, { method: 'POST', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) { showToast('Proxy stopped', 'success'); await loadAll(); }
        else showToast(data.detail || 'Failed to stop', 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

async function deleteProxy(id) {
    if (!confirm('Delete this proxy and its container?')) return;
    try {
        const res = await fetch(`/api/proxies/${id}`, { method: 'DELETE', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) { showToast('Proxy deleted', 'success'); await loadAll(); }
        else showToast(data.detail || 'Failed to delete', 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

async function testProxy(id) {
    showToast('Testing proxy...', 'success');
    try {
        const res = await fetch(`/api/proxies/${id}/test`, { method: 'POST', credentials: 'same-origin' });
        const data = await res.json();
        if (data.success) { showToast(`OK: ${data.ip} | ${data.ping}ms`, 'success'); await loadAll(); }
        else showToast(`Test failed: ${data.error || 'connection failed'}`, 'error');
    } catch (err) { showToast('Network error', 'error'); }
}

function showSection(name) {
    document.querySelectorAll('.section').forEach(s => s.style.display = 'none');
    document.querySelectorAll('.nav-links a').forEach(a => a.classList.remove('active'));
    document.getElementById('section-' + name).style.display = 'block';
    document.getElementById('nav-' + name)?.classList.add('active');
}

function showTab(name, ev) {
    document.querySelectorAll('.tab-content').forEach(t => t.style.display = 'none');
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.getElementById('tab-' + name).style.display = 'block';
    (ev?.target || window.event?.target)?.classList.add('active');
}

function showToast(msg, type) {
    const toast = document.getElementById('toast');
    toast.textContent = msg;
    toast.className = 'toast ' + type;
    clearTimeout(showToast._timer);
    showToast._timer = setTimeout(() => { toast.className = 'toast'; }, 4200);
}

async function cp(text, el) {
    try {
        if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(text);
        else fallbackCopy(text);
        if (el) {
            const tag = el.querySelector('.ch');
            const old = tag ? tag.textContent : '';
            if (tag) tag.textContent = 'Copied';
            setTimeout(() => { if (tag) tag.textContent = old || 'Copy'; }, 1200);
        }
        showToast('Copied to clipboard', 'success');
    } catch (err) {
        fallbackCopy(text);
        showToast('Copied', 'success');
    }
}

function fallbackCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    document.body.removeChild(ta);
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = String(text ?? '');
    return div.innerHTML;
}
function escapeAttr(text) { return escapeHtml(text).replace(/"/g, '&quot;'); }
function escapeJs(text) { return String(text ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'").replace(/\n/g, ' '); }
