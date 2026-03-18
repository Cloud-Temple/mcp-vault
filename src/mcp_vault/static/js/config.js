/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Config & State
   ═══════════════════════════════════════════════════════════════════════ */

const API = '/admin/api';

const STATE = {
    token: '',
    perms: [],
    clientName: '',
    version: '',
    currentPage: 'dashboard',
    activityTimer: null,
};

function getHeaders() {
    return { 'Authorization': `Bearer ${STATE.token}`, 'Content-Type': 'application/json' };
}

function isAdmin() { return STATE.perms.includes('admin'); }
function canWrite() { return isAdmin() || STATE.perms.includes('write'); }

function esc(s) {
    if (!s) return '';
    const d = document.createElement('div');
    d.textContent = String(s);
    return d.innerHTML;
}

function fmtDate(iso) {
    if (!iso) return '—';
    try { return new Date(iso).toLocaleDateString('fr-FR', { day:'2-digit', month:'2-digit', year:'numeric', hour:'2-digit', minute:'2-digit' }); }
    catch { return iso; }
}
