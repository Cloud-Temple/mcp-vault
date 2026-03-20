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

let auditFilter = { category: '', status: '', client: '', vault_id: '' };
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

    if (auditFilter.category || auditFilter.status || auditFilter.client || auditFilter.vault_id) {
        html += `<button class="btn btn-sm btn-ghost" onclick="clearAuditFilters()">✕ Reset</button>`;
    }

    html += `<span style="margin-left:auto;color:var(--muted);font-size:0.75rem">${entries.length} résultat(s)</span>`;
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
            html += `<div class="audit-tool">${esc(e.tool || '?')}</div>`;

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

function clearAuditFilters() {
    auditFilter = { category: '', status: '', client: '', vault_id: '' };
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
