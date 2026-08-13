/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — API Client & Auth
   ═══════════════════════════════════════════════════════════════════════ */

async function api(endpoint, opts = {}) {
    const r = await fetch(`${API}${endpoint}`, { headers: getHeaders(), ...opts });
    return r.json();
}

/* Un coffre DÉGRADÉ doit rester administrable — c'est même le moment où la
   console est la plus utile (diagnostiquer, desceller). Depuis l'issue #103,
   /admin/api/health renvoie `degraded` quand la disponibilité ne l'est pas :
   refuser cette valeur enfermerait l'exploitant dehors pendant l'incident.
   Seule une réponse qui n'est NI `ok` NI `degraded` (jeton invalide, refus,
   corps inattendu) invalide l'authentification. */
function healthAllowsLogin(status) {
    return status === 'ok' || status === 'degraded';
}

/* ─── Login ─── */
async function doLogin(token) {
    STATE.token = token;
    try {
        const health = await api('/health');
        if (!healthAllowsLogin(health.status)) throw new Error('bad');
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
        document.getElementById('loginToken').value = '';
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

/* Export pour le test Node ; ignoré dans le navigateur (module y est undefined). */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { healthAllowsLogin: healthAllowsLogin };
}
