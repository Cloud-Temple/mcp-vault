/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Activity View (auto-refresh)
   ═══════════════════════════════════════════════════════════════════════ */

async function loadActivity() {
    const el = document.getElementById('page-activity');
    const data = await api('/logs');
    const logs = (data.logs || []).reverse();

    let html = '<div class="flex-between" style="margin-bottom:1rem">';
    html += '<h2 style="color:var(--accent)">📡 Activité récente</h2>';
    html += '<span class="badge badge-info">Auto-refresh 5s</span>';
    html += '</div><div class="card">';

    if (logs.length === 0) {
        html += '<div class="empty-state">Aucune activité enregistrée</div>';
    } else {
        for (const l of logs) {
            const sc = l.status < 300 ? 's2xx' : l.status < 500 ? 's4xx' : 's5xx';
            html += `<div class="log-entry">
                <span class="log-method ${l.method}">${l.method}</span>
                ${esc(l.path)}
                → <span class="log-status ${sc}">${l.status}</span>
                <span class="log-time">(${l.duration_ms}ms)</span>
            </div>`;
        }
    }

    html += '</div>';
    el.innerHTML = html;
}
