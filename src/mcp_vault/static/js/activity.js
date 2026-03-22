/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Audit & Activity View (Phase 8c)
   Timeline magnifique avec filtres, statistiques et colorisation
   ═══════════════════════════════════════════════════════════════════════ */

const CATEGORY_ICONS = {
    system: '⚙️', vault: '🏛️', secret: '🔑', ssh: '🔏',
    policy: '📋', token: '🎫', audit: '📊', other: '📌',
};

const CATEGORY_COLORS = {
    system: '#8899aa', vault: '#41a890', secret: '#f39c12',
    ssh: '#9b59b6', policy: '#3498db', token: '#e67e22',
    audit: '#95a5a6', other: '#7f8c8d',
};

const STATUS_STYLES = {
    ok: { icon: '✅', cls: 'audit-ok' },
    created: { icon: '🆕', cls: 'audit-created' },
    deleted: { icon: '🗑️', cls: 'audit-deleted' },
    updated: { icon: '✏️', cls: 'audit-updated' },
    error: { icon: '❌', cls: 'audit-error' },
    denied: { icon: '🚫', cls: 'audit-denied' },
};

const TOOL_LABELS = {
    system_health: 'Vérification santé', system_about: 'Infos service',
    vault_create: 'Création vault', vault_list: 'Liste vaults', vault_info: 'Détails vault',
    vault_update: 'Modification vault', vault_delete: 'Suppression vault',
    secret_write: 'Écriture secret', secret_read: 'Lecture secret',
    secret_list: 'Liste secrets', secret_delete: 'Suppression secret',
    secret_types: 'Types de secrets', secret_generate_password: 'Génération mot de passe',
    ssh_ca_setup: 'Setup SSH CA', ssh_sign_key: 'Signature clé SSH',
    ssh_ca_public_key: 'Clé publique CA', ssh_ca_list_roles: 'Liste rôles SSH',
    ssh_ca_role_info: 'Détails rôle SSH',
    policy_create: 'Création policy', policy_list: 'Liste policies',
    policy_get: 'Détails policy', policy_delete: 'Suppression policy',
    token_update: 'Modification token', audit_log: 'Consultation audit',
};

let auditFilter = { category: '', status: '', client: '', vault_id: '', since: '' };
let auditAutoRefresh = null;

async function loadActivity() {
    const el = document.getElementById('page-activity');

    // Build query string from filters
    const params = new URLSearchParams();
    params.set('limit', '200');
    if (auditFilter.category) params.set('category', auditFilter.category);
    if (auditFilter.status) params.set('status', auditFilter.status);
    if (auditFilter.client) params.set('client', auditFilter.client);
    if (auditFilter.vault_id) params.set('vault_id', auditFilter.vault_id);
    if (auditFilter.since) params.set('since', auditFilter.since);

    const data = await api(`/audit?${params.toString()}`);
    const entries = data.entries || [];
    const stats = data.stats || {};

    let html = '';

    // ── Header avec statistiques ──
    html += '<div class="flex-between" style="margin-bottom:1rem">';
    html += '<h2 style="color:var(--accent)">📊 Journal d\'audit</h2>';
    html += '<div style="display:flex;gap:0.5rem;align-items:center">';
    html += `<span class="badge badge-info">${data.total_in_buffer || 0} événements</span>`;
    html += `<button class="btn btn-sm btn-ghost" onclick="toggleAuditRefresh()" id="btnAutoRefresh" title="Auto-refresh">🔄 Auto</button>`;
    html += '</div></div>';

    // ── Stats cards ──
    if (stats.by_category && Object.keys(stats.by_category).length > 0) {
        html += '<div class="stats-grid" style="margin-bottom:1rem">';
        for (const [cat, count] of Object.entries(stats.by_category)) {
            const icon = CATEGORY_ICONS[cat] || '📌';
            const color = CATEGORY_COLORS[cat] || '#888';
            html += `<div class="stat-card" style="cursor:pointer;border-color:${auditFilter.category === cat ? color : 'var(--border)'}" onclick="filterAuditCategory('${cat}')">
                <div class="stat-value" style="color:${color};font-size:1.4rem">${icon} ${count}</div>
                <div class="stat-label">${cat}</div>
            </div>`;
        }
        html += '</div>';
    }

    // ── Filtres actifs ──
    html += '<div class="card" style="padding:0.6rem 1rem;margin-bottom:0.8rem;display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">';
    html += '<span style="color:var(--text2);font-size:0.8rem">Filtres :</span>';

    // Category filter
    html += `<select class="audit-filter-select" onchange="filterAuditCategory(this.value)" style="padding:0.2rem 0.4rem;font-size:0.75rem;border-radius:4px;background:var(--bg);color:var(--text);border:1px solid var(--border)">`;
    html += `<option value="">Toutes catégories</option>`;
    for (const cat of ['system', 'vault', 'secret', 'ssh', 'policy', 'token']) {
        const sel = auditFilter.category === cat ? 'selected' : '';
        html += `<option value="${cat}" ${sel}>${CATEGORY_ICONS[cat]} ${cat}</option>`;
    }
    html += '</select>';

    // Status filter
    html += `<select onchange="filterAuditStatus(this.value)" style="padding:0.2rem 0.4rem;font-size:0.75rem;border-radius:4px;background:var(--bg);color:var(--text);border:1px solid var(--border)">`;
    html += `<option value="">Tous statuts</option>`;
    for (const [st, info] of Object.entries(STATUS_STYLES)) {
        const sel = auditFilter.status === st ? 'selected' : '';
        html += `<option value="${st}" ${sel}>${info.icon} ${st}</option>`;
    }
    html += '</select>';

    // Quick shortcut: Alerts only
    const alertActive = auditFilter.status === 'denied' || auditFilter.status === 'error';
    html += `<button class="btn btn-sm ${alertActive ? 'btn-danger' : 'btn-ghost'}" onclick="filterAuditAlerts()" title="Afficher uniquement denied + error" style="font-size:0.75rem;${alertActive ? 'background:#c0392b;color:white;' : ''}">🚨 Alertes</button>`;

    // Time range quick-select
    html += '<span style="color:var(--border);margin:0 0.2rem">│</span>';
    html += '<span style="color:var(--text2);font-size:0.75rem">Période :</span>';
    const ranges = [
        { label: '5m', minutes: 5 },
        { label: '15m', minutes: 15 },
        { label: '1h', minutes: 60 },
        { label: '24h', minutes: 1440 },
    ];
    for (const r of ranges) {
        const sinceVal = new Date(Date.now() - r.minutes * 60000).toISOString();
        const isActive = auditFilter.since && Math.abs(new Date(auditFilter.since).getTime() - new Date(sinceVal).getTime()) < 60000;
        html += `<button class="btn btn-sm btn-ghost" onclick="filterAuditSince(${r.minutes})" style="font-size:0.7rem;padding:0.15rem 0.4rem;${isActive ? 'color:var(--accent);border-color:var(--accent);' : ''}">${r.label}</button>`;
    }
    if (auditFilter.since) {
        html += `<button class="btn btn-sm btn-ghost" onclick="filterAuditSince(0)" style="font-size:0.7rem;padding:0.15rem 0.3rem">✕</button>`;
    }

    if (auditFilter.category || auditFilter.status || auditFilter.client || auditFilter.vault_id || auditFilter.since) {
        html += `<button class="btn btn-sm btn-ghost" onclick="clearAuditFilters()" style="margin-left:0.3rem">✕ Reset tout</button>`;
    }

    // Count with alert highlight
    const deniedCount = entries.filter(e => e.status === 'denied' || e.status === 'error').length;
    html += '<span style="margin-left:auto;font-size:0.75rem">';
    html += `<span style="color:var(--muted)">${entries.length} résultat(s)</span>`;
    if (deniedCount > 0) {
        html += ` <span style="color:#e74c3c;font-weight:bold">⚠️ ${deniedCount} alerte(s)</span>`;
    }
    html += '</span>';
    html += '</div>';

    // ── Timeline ──
    html += '<div class="card" style="padding:0">';

    if (entries.length === 0) {
        html += '<div class="empty-state">Aucun événement d\'audit</div>';
    } else {
        html += '<div class="audit-timeline">';
        let lastDate = '';

        for (const e of entries) {
            // Date separator
            const date = (e.ts || '').substring(0, 10);
            if (date !== lastDate) {
                html += `<div class="audit-date-sep">${formatDate(date)}</div>`;
                lastDate = date;
            }

            const time = (e.ts || '').substring(11, 19);
            const catIcon = CATEGORY_ICONS[e.category] || '📌';
            const catColor = CATEGORY_COLORS[e.category] || '#888';
            const stInfo = STATUS_STYLES[e.status] || { icon: '❓', cls: '' };

            html += `<div class="audit-entry ${stInfo.cls}">`;
            html += `<div class="audit-time">${time}</div>`;
            html += `<div class="audit-icon" style="color:${catColor}">${catIcon}</div>`;
            html += '<div class="audit-content">';
            const toolLabel = TOOL_LABELS[e.tool] || e.tool || '?';
            const toolTechnical = (TOOL_LABELS[e.tool] && e.tool !== toolLabel) ? ` <span style="color:var(--muted);font-size:0.7rem;font-weight:normal">${esc(e.tool)}</span>` : '';
            html += `<div class="audit-tool">${esc(toolLabel)}${toolTechnical}</div>`;

            // Detail line
            const parts = [];
            if (e.client) parts.push(`<span class="audit-tag audit-tag-client" title="Client">${esc(e.client)}</span>`);
            if (e.vault_id) parts.push(`<span class="audit-tag audit-tag-vault" title="Vault" onclick="filterAuditVault('${esc(e.vault_id)}')">${esc(e.vault_id)}</span>`);
            if (e.detail) parts.push(`<span class="audit-detail-text">${esc(e.detail)}</span>`);

            if (parts.length > 0) {
                html += `<div class="audit-meta">${parts.join(' ')}</div>`;
            }

            html += '</div>';
            html += `<div class="audit-status ${stInfo.cls}">${stInfo.icon}</div>`;
            if (e.duration_ms > 0) {
                html += `<div class="audit-duration">${e.duration_ms}ms</div>`;
            }
            html += '</div>';
        }

        html += '</div>';
    }

    html += '</div>';
    el.innerHTML = html;
}

function formatDate(dateStr) {
    if (!dateStr) return '';
    const today = new Date().toISOString().substring(0, 10);
    const yesterday = new Date(Date.now() - 86400000).toISOString().substring(0, 10);
    if (dateStr === today) return '📅 Aujourd\'hui';
    if (dateStr === yesterday) return '📅 Hier';
    return `📅 ${dateStr}`;
}

function filterAuditCategory(cat) {
    auditFilter.category = (auditFilter.category === cat) ? '' : cat;
    loadActivity();
}

function filterAuditStatus(st) {
    auditFilter.status = st;
    loadActivity();
}

function filterAuditVault(vid) {
    auditFilter.vault_id = (auditFilter.vault_id === vid) ? '' : vid;
    loadActivity();
}

function filterAuditSince(minutes) {
    if (minutes <= 0) {
        auditFilter.since = '';
    } else {
        auditFilter.since = new Date(Date.now() - minutes * 60000).toISOString();
    }
    loadActivity();
}

function filterAuditAlerts() {
    if (auditFilter.status === 'denied') {
        auditFilter.status = 'error';
    } else if (auditFilter.status === 'error') {
        auditFilter.status = '';
    } else {
        auditFilter.status = 'denied';
    }
    loadActivity();
}

function clearAuditFilters() {
    auditFilter = { category: '', status: '', client: '', vault_id: '', since: '' };
    loadActivity();
}

function toggleAuditRefresh() {
    const btn = document.getElementById('btnAutoRefresh');
    if (auditAutoRefresh) {
        clearInterval(auditAutoRefresh);
        auditAutoRefresh = null;
        if (btn) btn.style.color = 'var(--text2)';
    } else {
        auditAutoRefresh = setInterval(loadActivity, 5000);
        if (btn) btn.style.color = 'var(--accent)';
    }
}
