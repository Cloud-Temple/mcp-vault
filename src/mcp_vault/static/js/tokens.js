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
    html += '<div>';
    if (tokens.some(t => t.revoked)) {
        html += '<button class="btn btn-danger" style="margin-right:0.4rem" onclick="purgeRevokedTokens()" title="Supprimer définitivement les tokens révoqués depuis longtemps">🧹 Purger révoqués</button>';
    }
    html += '<button class="btn btn-primary" onclick="openCreateTokenModal()">+ Nouveau token</button>';
    html += '</div>';
    html += '</div>';

    html += '<div id="newTokenResult"></div>';

    if (tokens.length === 0) {
        html += '<div class="empty-state">Aucun token configuré</div>';
    } else {
        html += '<div class="card" style="padding:0;overflow-x:auto"><table>';
        html += '<thead><tr><th>Client</th><th>Permissions</th><th>Vaults</th><th>Policy</th><th>Créé le</th><th title="Empreinte du token (hash), non utilisable pour se connecter">Hash</th><th>Statut</th><th>Actions</th></tr></thead><tbody>';
        for (const t of tokens) {
            const policyBadge = t.policy_id
                ? `<span class="badge badge-info" title="Policy : ${esc(t.policy_id)}" style="cursor:pointer" onclick="event.stopPropagation();navigate('policies');setTimeout(()=>selectPolicy('${esc(t.policy_id)}'),300)">${esc(t.policy_id)}</span>`
                : '<span style="color:var(--muted);font-size:0.75rem">aucune</span>';

            // Dates formatées
            const createdAt = t.created_at ? new Date(t.created_at).toLocaleDateString('fr-FR', {day:'2-digit',month:'2-digit',year:'numeric'}) : '';
            const createdTime = t.created_at ? new Date(t.created_at).toLocaleTimeString('fr-FR', {hour:'2-digit',minute:'2-digit'}) : '';

            // Statut avec date de révocation
            let statusHtml;
            if (t.revoked) {
                const revokedAt = t.revoked_at ? new Date(t.revoked_at).toLocaleDateString('fr-FR', {day:'2-digit',month:'2-digit',year:'numeric'}) : '';
                statusHtml = `<span class="badge badge-err">révoqué</span>${revokedAt ? `<br><span style="color:var(--muted);font-size:0.68rem">${revokedAt}</span>` : ''}`;
            } else if (t.expired) {
                const expiresAt = t.expires_at ? new Date(t.expires_at).toLocaleDateString('fr-FR', {day:'2-digit',month:'2-digit',year:'numeric'}) : '';
                statusHtml = `<span class="badge badge-warn" title="Token expiré — connexions refusées">expiré</span>${expiresAt ? `<br><span style="color:var(--muted);font-size:0.68rem">${expiresAt}</span>` : ''}`;
            } else {
                statusHtml = '<span class="badge badge-ok">actif</span>';
            }

            html += `<tr>
                <td><strong>${esc(t.client_name)}</strong>${t.email ? `<br><span style="color:var(--muted);font-size:0.75rem">${esc(t.email)}</span>` : ''}</td>
                <td>${(t.permissions||[]).map(p => `<span class="badge ${p==='admin'?'badge-warn':p==='write'?'badge-info':'badge-ok'}">${p}</span>`).join(' ')}</td>
                <td>${t.allowed_resources && t.allowed_resources.length ? t.allowed_resources.map(r => `<code style="font-size:0.75rem">${esc(r)}</code>`).join(', ') : '<span style="color:var(--muted);font-size:0.75rem" title="Accès uniquement aux vaults créés par ce token">owner</span>'}</td>
                <td>${policyBadge}</td>
                <td><span style="font-size:0.78rem">${createdAt}</span>${createdTime ? `<br><span style="color:var(--muted);font-size:0.68rem">${createdTime}</span>` : ''}</td>
                <td><code style="font-size:0.75rem">${esc(t.hash_prefix || '')}…</code></td>
                <td>${statusHtml}</td>
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

    // Expiration (issue #65) : contrat STRICT via parseExpiresInDays (expires.js).
    // Vide → 90 ; "0" → jamais ; sinon entier [1,36500]. Toute saisie invalide (float,
    // texte, négatif, hors borne) → null → on BLOQUE l'envoi (fail-close), on ne coerce pas.
    const expiresDays = parseExpiresInDays(document.getElementById('ctExpires').value);
    if (expiresDays === null) {
        alert('Expiration invalide : saisir un entier de jours entre 0 (jamais) et ' + EXPIRES_MAX_DAYS + '.');
        return;
    }

    const body = {
        client_name: document.getElementById('ctName').value.trim(),
        permissions: perms,
        allowed_resources: vList,
        email: document.getElementById('ctEmail').value.trim(),
        expires_in_days: expiresDays,
    };

    if (policyId) {
        body.policy_id = policyId;
    }

    if (!body.client_name) { alert('Nom du client requis'); return; }

    const data = await api('/tokens', { method: 'POST', body: JSON.stringify(body) });
    closeModal('modalCreateToken');

    // Recharger la liste AVANT d'afficher le token (sinon loadTokens écrase le DOM)
    await loadTokens();

    if (data.status === 'created' && data.raw_token) {
        const el = document.getElementById('newTokenResult');
        if (el) {
            el.innerHTML = `<div class="card" style="border-color:var(--accent)">
                <h2>✅ Token créé pour "${esc(body.client_name)}"</h2>
                <p style="color:var(--danger);font-size:0.8rem">⚠️ Ce token ne sera affiché qu'<strong>une seule fois</strong>. Copiez-le maintenant.</p>
                <div class="token-display">
                    <span id="newTokenValue">${esc(data.raw_token)}</span>
                    <button class="copy-btn" onclick="copyNewToken()">📋 Copier</button>
                </div>
                <div style="margin-top:0.6rem;font-size:0.78rem;color:var(--text2)">
                    <span>🔑 Hash : <code>${esc(data.hash ? data.hash.substring(0,12) : '')}…</code></span>
                    ${data.expires_at ? `<span style="margin-left:1rem">📅 Expire : ${new Date(data.expires_at).toLocaleDateString('fr-FR')}</span>` : '<span style="margin-left:1rem">📅 Expire : jamais</span>'}
                    ${policyId ? `<span style="margin-left:1rem">📋 Policy : <strong>${esc(policyId)}</strong></span>` : ''}
                </div>
            </div>`;
            // Scroll vers le token affiché
            el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }
}

async function revokeToken(hashPrefix) {
    if (!confirm(`Révoquer le token ${hashPrefix}… ? Irréversible.`)) return;
    await api(`/tokens/${hashPrefix}`, { method: 'DELETE' });
    loadTokens();
}

async function purgeRevokedTokens() {
    // Étape 1 : dry-run pour obtenir le décompte (rétention appliquée côté serveur)
    const preview = await api('/tokens/purge', { method: 'POST', body: JSON.stringify({ dry_run: true }) });
    if (preview.status !== 'ok') { alert('Erreur: ' + (preview.message || 'dry-run impossible')); return; }
    const n = preview.count || 0;
    const days = (preview.older_than_days != null) ? preview.older_than_days : 30;
    if (n === 0) { alert(`Aucun token révoqué depuis plus de ${days} jours à purger.`); return; }
    // Étape 2 : confirmation explicite — irréversible
    if (!confirm(`Purger DÉFINITIVEMENT ${n} token(s) révoqué(s) depuis plus de ${days} jours ?\n\nIrréversible. (La révocation, elle, reste réversible tant que le token n'est pas purgé.)`)) return;
    // Étape 3 : exécution
    const res = await api('/tokens/purge', { method: 'POST', body: JSON.stringify({ dry_run: false }) });
    if (res.status === 'ok') {
        loadTokens();
    } else {
        alert('Erreur: ' + (res.message || 'purge non persistée (S3 indisponible)'));
    }
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

    // Charger les policies disponibles
    if (isAdmin()) {
        await loadPolicyOptions('etPolicy');
    }

    // Sélectionner la policy du token — TOUJOURS remettre la valeur (même "" pour "aucune"),
    // sinon le select conserve la valeur du modal précédent.
    const etPolicySelect = document.getElementById('etPolicy');
    if (etPolicySelect) {
        if (policyId) {
            // S'assurer que la policy actuelle est bien dans la liste (cas rare)
            let found = false;
            for (const opt of etPolicySelect.options) {
                if (opt.value === policyId) { found = true; break; }
            }
            if (!found) {
                const opt = document.createElement('option');
                opt.value = policyId;
                opt.textContent = policyId + ' (actuelle)';
                etPolicySelect.appendChild(opt);
            }
        }
        etPolicySelect.value = policyId || '';  // "" = "— Aucune policy —"
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

    // Toujours envoyer policy_id : "" = retirer la policy, valeur = assigner.
    // Ne jamais envoyer "_remove" — le backend admin API ne le comprend pas
    // (le sentinel _remove n'est géré que par l'outil MCP token_update).
    body.policy_id = policyId;

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
