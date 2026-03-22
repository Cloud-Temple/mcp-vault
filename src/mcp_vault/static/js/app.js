/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — App (Navigation, Sidebar, Init)
   ═══════════════════════════════════════════════════════════════════════ */

/* ─── Sidebar builder ─── */
function buildSidebar() {
    const nav = document.getElementById('sidebarNav');
    let html = `
        <button onclick="navigate('dashboard')" id="nav-dashboard" class="active">📊 <span>Dashboard</span></button>
        <button onclick="navigate('vaults')" id="nav-vaults">🗄️ <span>Vaults</span></button>`;

    if (isAdmin()) {
        html += `
        <div class="sidebar-section">Administration</div>
        <button onclick="navigate('tokens')" id="nav-tokens">🔑 <span>Tokens</span></button>`;
    }

    html += `
        <div class="sidebar-section">Monitoring</div>
        <button onclick="navigate('activity')" id="nav-activity">📡 <span>Activité</span></button>`;

    nav.innerHTML = html;
}

/* ─── Navigation ─── */
function navigate(page) {
    STATE.currentPage = page;
    if (STATE.activityTimer) { clearInterval(STATE.activityTimer); STATE.activityTimer = null; }

    // Hide all pages
    document.querySelectorAll('[id^="page-"]').forEach(el => el.classList.add('hidden'));
    // Deactivate all nav
    document.querySelectorAll('.sidebar-nav button').forEach(el => el.classList.remove('active'));

    // Show target
    const target = document.getElementById(`page-${page}`);
    if (target) target.classList.remove('hidden');
    const nav = document.getElementById(`nav-${page}`);
    if (nav) nav.classList.add('active');

    // Load data
    if (page === 'dashboard') loadDashboard();
    else if (page === 'vaults') loadVaults();
    else if (page === 'tokens') loadTokens();
    else if (page === 'activity') { loadActivity(); STATE.activityTimer = setInterval(loadActivity, 5000); }

    window.location.hash = page;
}

/* ─── Init ─── */
document.addEventListener('DOMContentLoaded', () => {
    // Login form
    document.getElementById('loginForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        const token = document.getElementById('loginToken').value.trim();
        if (!token) return;
        const ok = await doLogin(token);
        if (!ok) {
            const err = document.getElementById('loginError');
            err.textContent = 'Token invalide ou non autorisé';
            setTimeout(() => err.textContent = '', 3000);
        }
    });

    // Modal backdrop close
    document.querySelectorAll('.modal-overlay').forEach(el => {
        el.addEventListener('click', (e) => { if (e.target === el) el.classList.remove('active'); });
    });

    // Auto-login
    tryAutoLogin();
});
