/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Dashboard View
   ═══════════════════════════════════════════════════════════════════════ */

async function loadDashboard() {
    const el = document.getElementById('page-dashboard');
    el.innerHTML = '<div class="empty-state">Chargement…</div>';

    const [health, vaults, tokens] = await Promise.all([
        api('/health'), api('/vaults'), api('/tokens').catch(() => ({ tokens: [] }))
    ]);

    const vc = vaults.count || 0;
    const tc = (tokens.tokens || []).filter(t => !t.revoked).length;
    const sc = (vaults.vaults || []).reduce((s, v) => s + (v.secrets_count || 0), 0);

    el.innerHTML = `
        <div class="stats-grid" style="margin-bottom:1.2rem">
            <div class="stat-card"><div class="stat-value">${health.status === 'ok' ? '✅' : '❌'}</div><div class="stat-label">Service</div></div>
            <div class="stat-card"><div class="stat-value">${vc}</div><div class="stat-label">Vaults</div></div>
            <div class="stat-card"><div class="stat-value">${sc}</div><div class="stat-label">Secrets</div></div>
            <div class="stat-card"><div class="stat-value">${tc}</div><div class="stat-label">Tokens</div></div>
            <div class="stat-card"><div class="stat-value">${health.tools_count || 0}</div><div class="stat-label">Outils MCP</div></div>
            <div class="stat-card"><div class="stat-value">${health.s3_configured ? '✅' : '❌'}</div><div class="stat-label">S3</div></div>
        </div>
        <div class="card">
            <h2>🛠️ Outils MCP</h2>
            <div style="display:flex;flex-wrap:wrap;gap:0.4rem">
                ${(health.tools || []).map(t => `<span class="badge badge-info">${t}</span>`).join('')}
            </div>
        </div>
        <div class="card">
            <h2>ℹ️ Informations</h2>
            <table>
                <tr><td style="color:var(--muted)">Version</td><td>${esc(health.version)}</td></tr>
                <tr><td style="color:var(--muted)">Python</td><td>${esc(health.python_version)}</td></tr>
                <tr><td style="color:var(--muted)">Service</td><td>${esc(health.service_name)}</td></tr>
                <tr><td style="color:var(--muted)">Identité</td><td>${esc(STATE.clientName)} (${STATE.perms.join(', ')})</td></tr>
            </table>
        </div>`;
}
