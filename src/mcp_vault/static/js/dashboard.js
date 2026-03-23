/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Dashboard View
   ═══════════════════════════════════════════════════════════════════════ */

async function loadDashboard() {
    const el = document.getElementById('page-dashboard');
    el.innerHTML = '<div class="empty-state">Chargement…</div>';

    const promises = [
        api('/health'), api('/vaults'), api('/tokens').catch(() => ({ tokens: [] }))
    ];
    // Charger les policies si admin
    if (isAdmin()) promises.push(api('/policies').catch(() => ({ policies: [] })));

    const [health, vaults, tokens, policies] = await Promise.all(promises);

    const vc = vaults.count || 0;
    const tc = (tokens.tokens || []).filter(t => !t.revoked).length;
    const sc = (vaults.vaults || []).reduce((s, v) => s + (v.secrets_count || 0), 0);
    const pc = policies ? (policies.policies || []).length : 0;

    el.innerHTML = `
        <div class="stats-grid" style="margin-bottom:1.2rem">
            <div class="stat-card"><div class="stat-value">${health.status === 'ok' ? '✅' : '❌'}</div><div class="stat-label">Service</div></div>
            <div class="stat-card" style="cursor:pointer" onclick="navigate('vaults')"><div class="stat-value">${vc}</div><div class="stat-label">Vaults</div></div>
            <div class="stat-card"><div class="stat-value">${sc}</div><div class="stat-label">Secrets</div></div>
            ${isAdmin() ? `<div class="stat-card" style="cursor:pointer" onclick="navigate('policies')"><div class="stat-value">${pc}</div><div class="stat-label">Policies</div></div>` : ''}
            <div class="stat-card" ${isAdmin() ? 'style="cursor:pointer" onclick="navigate(\'tokens\')"' : ''}><div class="stat-value">${tc}</div><div class="stat-label">Tokens</div></div>
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
        </div>
        <div class="card">
            <div class="flex-between">
                <h2>🎲 Générateur de mot de passe</h2>
                <button class="btn btn-primary btn-sm" onclick="dashGeneratePassword()">Générer (24 car.)</button>
            </div>
            <div id="dashPasswordResult" style="margin-top:0.5rem"></div>
            <div class="help-text" style="margin-top:0.3rem">Génère un mot de passe CSPRNG de 24 caractères (majuscules, minuscules, chiffres, symboles).</div>
        </div>
        <div class="card">
            <h2>📋 Types de secrets supportés (14)</h2>
            <div class="help-text" style="margin-bottom:0.6rem">Chaque type définit les champs obligatoires et optionnels. Utilisé lors de la création de secrets.</div>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(250px,1fr));gap:0.5rem">
                ${_renderSecretTypesReference()}
            </div>
        </div>`;
}

/* ─── Générateur standalone ─── */
async function dashGeneratePassword() {
    const el = document.getElementById('dashPasswordResult');
    if (!el) return;
    el.innerHTML = '<span style="color:var(--muted)">Génération…</span>';
    try {
        const data = await api('/generate-password');
        if (data.password) {
            el.innerHTML = `<div class="token-display" style="border-color:var(--success)">
                <span id="dashPwValue">${esc(data.password)}</span>
                <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('dashPwValue').textContent).then(()=>{this.textContent='✅';setTimeout(()=>this.textContent='📋',1500)})">📋</button>
            </div>`;
        }
    } catch (e) {
        el.innerHTML = '<span style="color:var(--danger)">Erreur de génération</span>';
    }
}

/* ─── Référence des 14 types ─── */
function _renderSecretTypesReference() {
    if (typeof SECRET_TYPE_FIELDS === 'undefined') return '';
    let html = '';
    for (const [type, schema] of Object.entries(SECRET_TYPE_FIELDS)) {
        if (!schema) continue;
        const icon = schema.icon || '⚙️';
        const label = schema.label || type;
        const desc = schema.desc || '';
        const fields = schema.fields || [];

        const reqFields = fields.filter(f => f.required).map(f => f.name);
        const optFields = fields.filter(f => !f.required).map(f => f.name);

        html += `<div style="background:var(--bg);border:1px solid var(--border);border-radius:var(--radius);padding:0.5rem 0.7rem">
            <div style="font-weight:600;font-size:0.82rem;margin-bottom:0.2rem">${icon} ${esc(label)}</div>
            <div style="font-size:0.7rem;color:var(--text2);margin-bottom:0.3rem">${esc(desc)}</div>
            ${reqFields.length > 0 ? `<div style="font-size:0.68rem"><span style="color:var(--danger)">requis</span> : ${reqFields.map(f => `<code style="font-size:0.65rem">${esc(f)}</code>`).join(', ')}</div>` : ''}
            ${optFields.length > 0 ? `<div style="font-size:0.68rem;color:var(--muted)">optionnel : ${optFields.map(f => `<code style="font-size:0.65rem">${esc(f)}</code>`).join(', ')}</div>` : ''}
        </div>`;
    }
    return html;
}
