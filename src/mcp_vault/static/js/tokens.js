/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Tokens View (CRUD)
   Avec colonne Policy, select policy_id dans création/édition
   ═══════════════════════════════════════════════════════════════════════ */

async function loadTokens() {
    const el = document.getElementById('page-tokens');
    const data = await api('/tokens');
    const tokens = data.tokens || [];

    let html = '<div class="flex-between" style="margin-bottom:1rem">';
    html += '<h2 style="color:var(--accent)">🔑 Tokens d\'accès</h2>';
    html += '<button class="btn btn-primary" onclick="openCreateTokenModal()">+ Nouveau token</button>';
    html += '</div>';

    html += '<div id="newTokenResult"></div>';

    if (tokens.length === 0) {
        html += '<div class="empty-state">Aucun token configuré</div>';
    } else {
        html += '<div class="card" style="padding:0;overflow-x:auto"><table>';
        html += '<thead><tr><th>Client</th><th>Permissions</th><th>Vaults</th><th>Policy</th><th>Hash</th><th>Statut</th><th>Actions</th></tr></thead><tbody>';
        for (const t of tokens) {
            const policyBadge = t.policy_id
                ? `<span class="badge badge-info" title="Policy : ${esc(t.policy_id)}" style="cursor:pointer" onclick="event.stopPropagation();navigate('policies');setTimeout(()=>selectPolicy('${esc(t.policy_id)}'),300)">${esc(t.policy_id)}</span>`
                : '<span style="color:var(--muted);font-size:0.75rem">aucune</span>';

            html += `<tr>
                <td><strong>${esc(t.client_name)}</strong>${t.email ? `<br><span style="color:var(--muted);font-size:0.75rem">${esc(t.email)}</span>` : ''}</td>
                <td>${(t.permissions||[]).map(p => `<span class="badge ${p==='admin'?'badge-warn':p==='write'?'badge-info':'badge-ok'}">${p}</span>`).join(' ')}</td>
                <td>${t.allowed_resources && t.allowed_resources.length ? t.allowed_resources.map(r => `<code style="font-size:0.75rem">${esc(r)}</code>`).join(', ') : '<span style="color:var(--muted);font-size:0.75rem" title="Accès uniquement aux vaults créés par ce token">owner</span>'}</td>
                <td>${policyBadge}</td>
                <td><code style="font-size:0.75rem">${esc(t.hash_prefix || '')}…</code></td>
                <td>${t.revoked ? '<span class="badge badge-err">révoqué</span>' : '<span class="badge badge-ok">actif</span>'}</td>
                <td>${!t.revoked ? `<button onclick="openEditToken('${esc(t.hash_prefix)}', ${JSON.stringify(t.permissions||[]).replace(/"/g,'&quot;')}, '${esc((t.allowed_resources||[]).join(", "))}', '${esc(t.policy_id||"")}')" class="btn btn-sm" style="margin-right:0.3rem" title="Modifier">✏️</button><button onclick="revokeToken('${esc(t.hash_prefix)}')" class="btn btn-danger btn-sm" title="Révoquer">🗑️</button>` : ''}</td>
            </tr>`;
        }
        html += '</tbody></table></div>';
    }

    el.innerHTML = html;
}

/* ─── Ouvrir le modal de création avec chargement des policies ─── */
async function openCreateTokenModal() {
    // Reset form
    document.getElementById('ctName').value = '';
    document.getElementById('ctEmail').value = '';
    document.getElementById('ctExpires').value = '90';
    document.getElementById('ctVaults').value = '';
    document.getElementById('ctPermWrite').checked = false;
    document.getElementById('ctPermAdmin').checked = false;

    // Charger les policies disponibles
    if (isAdmin()) {
        await loadPolicyOptions('ctPolicy');
    }

    openModal('modalCreateToken');
}

async function doCreateToken() {
    const perms = ['read'];
    if (document.getElementById('ctPermWrite').checked) perms.push('write');
    if (document.getElementById('ctPermAdmin').checked) perms.push('admin');

    const vStr = document.getElementById('ctVaults').value.trim();
    const vList = vStr ? vStr.split(',').map(s => s.trim()).filter(Boolean) : [];

    const policyId = document.getElementById('ctPolicy')?.value || '';

    const body = {
        client_name: document.getElementById('ctName').value.trim(),
        permissions: perms,
        allowed_resources: vList,
        email: document.getElementById('ctEmail').value.trim(),
        expires_in_days: parseInt(document.getElementById('ctExpires').value) || 90,
    };

    if (policyId) {
        body.policy_id = policyId;
    }

    if (!body.client_name) { alert('Nom du client requis'); return; }

    const data = await api('/tokens', { method: 'POST', body: JSON.stringify(body) });
    closeModal('modalCreateToken');

    if (data.status === 'created' && data.token) {
        const el = document.getElementById('newTokenResult');
        if (el) {
            el.innerHTML = `<div class="card" style="border-color:var(--accent)">
                <h2>✅ Token créé pour "${esc(body.client_name)}"</h2>
                <p style="color:var(--danger);font-size:0.8rem">⚠️ Ce token ne sera affiché qu'<strong>une seule fois</strong>.</p>
                <div class="token-display">
                    <span id="newTokenValue">${esc(data.token)}</span>
                    <button class="copy-btn" onclick="copyNewToken()">📋 Copier</button>
                </div>
                ${policyId ? `<p style="font-size:0.8rem;color:var(--text2);margin-top:0.5rem">📋 Policy associée : <strong>${esc(policyId)}</strong></p>` : ''}
            </div>`;
        }
    }

    loadTokens();
}

async function revokeToken(hashPrefix) {
    if (!confirm(`Révoquer le token ${hashPrefix}… ? Irréversible.`)) return;
    await api(`/tokens/${hashPrefix}`, { method: 'DELETE' });
    loadTokens();
}

function copyNewToken() {
    const el = document.getElementById('newTokenValue');
    if (!el) return;
    navigator.clipboard.writeText(el.textContent).then(() => {
        const btn = el.parentElement.querySelector('.copy-btn');
        if (btn) { btn.textContent = '✅ Copié !'; setTimeout(() => btn.textContent = '📋 Copier', 2000); }
    });
}

// ═══════════════════════════════════════════════════════════════════════
// Token Update (edit modal)
// ═══════════════════════════════════════════════════════════════════════

async function openEditToken(hashPrefix, permissions, vaults, policyId) {
    // Populate the edit modal fields
    document.getElementById('etHashPrefix').value = hashPrefix;
    document.getElementById('etPermRead').checked = permissions.includes('read');
    document.getElementById('etPermWrite').checked = permissions.includes('write');
    document.getElementById('etPermAdmin').checked = permissions.includes('admin');
    document.getElementById('etVaults').value = vaults || '';

    // Charger les policies disponibles puis sélectionner la bonne
    if (isAdmin()) {
        await loadPolicyOptions('etPolicy');
    }

    // Ajouter l'option "_remove" pour retirer la policy
    const etPolicySelect = document.getElementById('etPolicy');
    if (etPolicySelect && policyId) {
        // S'assurer que la valeur actuelle est bien dans la liste
        let found = false;
        for (const opt of etPolicySelect.options) {
            if (opt.value === policyId) { found = true; break; }
        }
        if (!found && policyId) {
            const opt = document.createElement('option');
            opt.value = policyId;
            opt.textContent = policyId + ' (actuelle)';
            etPolicySelect.appendChild(opt);
        }
        etPolicySelect.value = policyId;
    }

    openModal('modalEditToken');
}

async function doUpdateToken() {
    const hashPrefix = document.getElementById('etHashPrefix').value;
    const perms = [];
    if (document.getElementById('etPermRead').checked) perms.push('read');
    if (document.getElementById('etPermWrite').checked) perms.push('write');
    if (document.getElementById('etPermAdmin').checked) perms.push('admin');

    const vStr = document.getElementById('etVaults').value.trim();
    const vList = vStr ? vStr.split(',').map(s => s.trim()).filter(Boolean) : [];
    const policyId = document.getElementById('etPolicy').value.trim();

    const body = {
        permissions: perms,
        allowed_resources: vList,
    };

    // Si policy sélectionnée, l'envoyer. Si vide et qu'il y en avait une, envoyer "_remove"
    if (policyId) {
        body.policy_id = policyId;
    } else {
        // Vide = retirer la policy (envoyer _remove)
        body.policy_id = '_remove';
    }

    const data = await api(`/tokens/${hashPrefix}`, {
        method: 'PUT',
        body: JSON.stringify(body),
    });

    closeModal('modalEditToken');

    if (data.status === 'updated') {
        loadTokens();
    } else {
        alert('Erreur: ' + (data.message || 'Échec de la mise à jour'));
    }
}
