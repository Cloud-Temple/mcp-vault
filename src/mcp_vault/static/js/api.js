/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — API Client & Auth
   ═══════════════════════════════════════════════════════════════════════ */

async function api(endpoint, opts = {}) {
    const r = await fetch(`${API}${endpoint}`, { headers: getHeaders(), ...opts });
    return r.json();
}

/* ─── Login ─── */
async function doLogin(token) {
    STATE.token = token;
    try {
        const health = await api('/health');
        if (health.status !== 'ok') throw new Error('bad');
        STATE.version = health.version || 'dev';

        // Get permissions via whoami
        const who = await api('/whoami');
        if (who.status === 'ok') {
            STATE.perms = who.permissions || ['read'];
            STATE.clientName = who.client_name || 'unknown';
        } else {
            STATE.perms = ['read', 'write', 'admin']; // fallback bootstrap
            STATE.clientName = 'admin';
        }

        sessionStorage.setItem('vault-admin-token', token);
        document.getElementById('loginOverlay').classList.add('hidden');
        document.getElementById('appMain').classList.remove('hidden');
        document.getElementById('headerVersion').textContent = `v${STATE.version}`;
        document.getElementById('headerUser').textContent = STATE.clientName;

        buildSidebar();
        navigate('dashboard');
        return true;
    } catch (e) {
        STATE.token = '';
        STATE.perms = [];
        return false;
    }
}

function logout() {
    STATE.token = '';
    STATE.perms = [];
    sessionStorage.removeItem('vault-admin-token');
    if (STATE.activityTimer) clearInterval(STATE.activityTimer);
    document.getElementById('appMain').classList.add('hidden');
    document.getElementById('loginOverlay').classList.remove('hidden');
    document.getElementById('loginToken').value = '';
}

/* ─── Auto-login ─── */
function tryAutoLogin() {
    const saved = sessionStorage.getItem('vault-admin-token');
    if (saved) doLogin(saved);
}

/* ─── Modal helpers ─── */
function openModal(id) { document.getElementById(id).classList.add('active'); }
function closeModal(id) { document.getElementById(id).classList.remove('active'); }
