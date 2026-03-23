/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Policies View (CRUD)
   Gestion des politiques d'accès avec path_rules
   ═══════════════════════════════════════════════════════════════════════ */

let _selectedPolicy = null;
let _availableTools = [];
let _pathRuleCount = 0;

/* ═══════════════════════════════════════════════════════════════════════
   Chargement de la vue Policies
   ═══════════════════════════════════════════════════════════════════════ */

async function loadPolicies() {
    const el = document.getElementById('page-policies');
    const data = await api('/policies');
    const policies = data.policies || [];

    let html = '<div class="flex-between" style="margin-bottom:1rem">';
    html += `<h2 style="color:var(--accent)">📋 Policies (${policies.length})</h2>`;
    html += '<button class="btn btn-primary" onclick="openCreatePolicyModal()">+ Nouvelle policy</button>';
    html += '</div>';

    if (policies.length === 0) {
        html += '<div class="empty-state">';
        html += '<p>Aucune policy configurée.</p>';
        html += '<p style="font-size:0.75rem;margin-top:0.5rem;color:var(--text2)">Les policies contrôlent les outils MCP accessibles et les chemins autorisés pour chaque token.</p>';
        html += '</div>';
    } else {
        html += '<div class="card" style="padding:0;overflow-x:auto"><table>';
        html += '<thead><tr><th>ID</th><th>Description</th><th>Mode</th><th>Outils</th><th>Règles de chemin</th><th>Actions</th></tr></thead><tbody>';
        for (const p of policies) {
            const mode = _getPolicyMode(p);
            const toolCount = _getPolicyToolCount(p);
            const pathRulesCount = (p.path_rules || []).length;

            html += `<tr style="cursor:pointer" onclick="selectPolicy('${esc(p.policy_id)}')">
                <td><strong style="color:var(--accent)">${esc(p.policy_id)}</strong></td>
                <td style="color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(p.description || '—')}</td>
                <td>${mode.badge}</td>
                <td>${toolCount}</td>
                <td>${pathRulesCount > 0 ? `<span class="badge badge-info">${pathRulesCount} règle(s)</span>` : '<span style="color:var(--muted)">—</span>'}</td>
                <td>
                    <button onclick="event.stopPropagation();deletePolicy('${esc(p.policy_id)}')" class="btn btn-danger btn-sm">🗑️</button>
                </td>
            </tr>`;
        }
        html += '</tbody></table></div>';
    }

    html += '<div id="policyDetail"></div>';
    el.innerHTML = html;

    // Reselect if was selected
    if (_selectedPolicy) selectPolicy(_selectedPolicy);
}

/* ─── Mode de la policy ─── */
function _getPolicyMode(policy) {
    const allowed = policy.allowed_tools || [];
    const denied = policy.denied_tools || [];
    if (allowed.length > 0 && denied.length === 0) {
        return { badge: '<span class="badge badge-ok">✅ Allow-list</span>', mode: 'allow' };
    } else if (denied.length > 0 && allowed.length === 0) {
        return { badge: '<span class="badge badge-warn">🚫 Deny-list</span>', mode: 'deny' };
    } else if (allowed.length > 0 && denied.length > 0) {
        return { badge: '<span class="badge badge-err">⚠️ Mixte</span>', mode: 'mixed' };
    }
    return { badge: '<span class="badge" style="background:rgba(102,102,128,0.15);color:var(--muted)">Aucune restriction</span>', mode: 'none' };
}

function _getPolicyToolCount(policy) {
    const allowed = policy.allowed_tools || [];
    const denied = policy.denied_tools || [];
    if (allowed.length > 0) return `<span class="badge badge-ok">${allowed.length} autorisé(s)</span>`;
    if (denied.length > 0) return `<span class="badge badge-warn">${denied.length} refusé(s)</span>`;
    return '<span style="color:var(--muted)">Tous</span>';
}

/* ═══════════════════════════════════════════════════════════════════════
   Détail d'une policy
   ═══════════════════════════════════════════════════════════════════════ */

async function selectPolicy(policyId) {
    _selectedPolicy = policyId;
    const el = document.getElementById('policyDetail');
    if (!el) return;
    el.innerHTML = '<div class="empty-state">Chargement…</div>';

    const data = await api(`/policies/${policyId}`);
    if (data.status === 'error') {
        el.innerHTML = `<div class="empty-state">Erreur : ${esc(data.message)}</div>`;
        return;
    }

    const allowed = data.allowed_tools || [];
    const denied = data.denied_tools || [];
    const pathRules = data.path_rules || [];

    let html = `<div class="card mt-1">
        <div class="flex-between">
            <h2>📋 ${esc(policyId)}</h2>
            <div style="display:flex;gap:0.4rem">
                <button class="btn btn-danger btn-sm" onclick="deletePolicy('${esc(policyId)}')">🗑️ Supprimer</button>
                <button class="btn btn-ghost btn-sm" onclick="_selectedPolicy=null;document.getElementById('policyDetail').innerHTML=''">✕</button>
            </div>
        </div>
        ${data.description ? `<p style="color:var(--text2);margin:0.5rem 0">${esc(data.description)}</p>` : ''}`;

    // ── Outils autorisés ──
    if (allowed.length > 0) {
        html += '<div style="margin:0.8rem 0"><h3 style="color:var(--success);font-size:0.85rem;margin-bottom:0.4rem">✅ Outils autorisés</h3>';
        html += '<div class="help-text">Seuls ces outils sont accessibles. Tous les autres sont bloqués.</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:0.3rem;margin-top:0.3rem">';
        for (const t of allowed) {
            html += `<span class="badge badge-ok">${esc(t)}</span>`;
        }
        html += '</div></div>';
    }

    // ── Outils refusés ──
    if (denied.length > 0) {
        html += '<div style="margin:0.8rem 0"><h3 style="color:var(--warning);font-size:0.85rem;margin-bottom:0.4rem">🚫 Outils refusés</h3>';
        html += '<div class="help-text">Ces outils sont bloqués. Tous les autres restent accessibles.</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:0.3rem;margin-top:0.3rem">';
        for (const t of denied) {
            html += `<span class="badge badge-warn">${esc(t)}</span>`;
        }
        html += '</div></div>';
    }

    if (allowed.length === 0 && denied.length === 0) {
        html += '<div style="margin:0.8rem 0;color:var(--muted)"><em>Aucune restriction sur les outils — tous sont accessibles.</em></div>';
    }

    // ── Règles de chemin (path_rules) ──
    if (pathRules.length > 0) {
        html += '<div style="margin:1rem 0"><h3 style="color:var(--accent);font-size:0.85rem;margin-bottom:0.4rem">🛤️ Règles de chemin</h3>';
        html += '<div class="help-text">Restriction d\'accès aux secrets par chemin (patterns <code>fnmatch</code>).</div>';

        for (const rule of pathRules) {
            html += '<div class="path-rule-card">';
            html += `<div class="path-rule-header">`;
            html += `<span class="path-rule-vault">${esc(rule.vault_pattern || '*')}</span>`;
            const perms = rule.permissions || [];
            html += '<div style="display:flex;gap:0.2rem">';
            for (const p of perms) {
                const cls = p === 'read' ? 'badge-ok' : p === 'write' ? 'badge-info' : 'badge-warn';
                html += `<span class="badge ${cls}">${esc(p)}</span>`;
            }
            html += '</div></div>';

            const paths = rule.allowed_paths || [];
            if (paths.length > 0) {
                html += '<div class="path-rule-paths">';
                html += '<span style="color:var(--muted);font-size:0.72rem">Chemins autorisés :</span>';
                for (const ap of paths) {
                    html += `<code class="path-pattern">${esc(ap)}</code>`;
                }
                html += '</div>';
            } else {
                html += '<div style="font-size:0.75rem;color:var(--muted);margin-top:0.3rem"><em>Tous les chemins sont autorisés dans ce vault</em></div>';
            }
            html += '</div>';
        }
        html += '</div>';
    }

    // ── Métadonnées ──
    html += '<table style="margin-top:0.8rem">';
    if (data.created_at) html += `<tr><td style="color:var(--muted);width:120px">Créé le</td><td>${fmtDate(data.created_at)}</td></tr>`;
    if (data.created_by) html += `<tr><td style="color:var(--muted)">Créé par</td><td>${esc(data.created_by)}</td></tr>`;
    html += '</table>';

    html += '</div>';
    el.innerHTML = html;
}

/* ═══════════════════════════════════════════════════════════════════════
   Création de policy
   ═══════════════════════════════════════════════════════════════════════ */

async function openCreatePolicyModal() {
    // Charger la liste des outils MCP disponibles
    if (_availableTools.length === 0) {
        const health = await api('/health');
        _availableTools = health.tools || [];
    }
    _pathRuleCount = 0;

    // Rendre les checkboxes d'outils dans le modal
    _renderToolCheckboxes();
    _renderPathRules();

    // Reset form
    document.getElementById('cpPolicyId').value = '';
    document.getElementById('cpDescription').value = '';
    document.getElementById('cpMode').value = 'deny';
    _updateToolModeVisibility();

    openModal('modalCreatePolicy');
}

function _renderToolCheckboxes() {
    const container = document.getElementById('cpToolsList');
    if (!container) return;

    // Catégoriser les outils
    const categories = {};
    for (const tool of _availableTools) {
        const prefix = tool.split('_')[0];
        const cat = { system: 'Système', vault: 'Vaults', secret: 'Secrets', ssh: 'SSH CA', policy: 'Policies', token: 'Tokens', audit: 'Audit' }[prefix] || 'Autres';
        if (!categories[cat]) categories[cat] = [];
        categories[cat].push(tool);
    }

    let html = '';
    for (const [cat, tools] of Object.entries(categories)) {
        html += `<div class="tool-category">`;
        html += `<div class="tool-category-header" onclick="toggleToolCategory(this)">
            <span>${cat}</span>
            <span class="tool-category-count">${tools.length}</span>
        </div>`;
        html += '<div class="tool-category-items">';
        for (const t of tools) {
            const label = TOOL_LABELS[t] || t;
            html += `<label class="tool-checkbox" title="${esc(t)}">
                <input type="checkbox" value="${esc(t)}">
                <span class="tool-name">${esc(label)}</span>
                <span class="tool-id">${esc(t)}</span>
            </label>`;
        }
        html += '</div></div>';
    }

    container.innerHTML = html;
}

function toggleToolCategory(header) {
    const items = header.nextElementSibling;
    if (items) items.classList.toggle('collapsed');
}

function _updateToolModeVisibility() {
    const mode = document.getElementById('cpMode').value;
    const label = document.getElementById('cpToolsLabel');
    const help = document.getElementById('cpToolsHelp');
    if (label) {
        if (mode === 'allow') {
            label.textContent = '✅ Outils autorisés';
            help.textContent = 'Seuls les outils cochés seront accessibles. Tous les autres seront bloqués.';
        } else if (mode === 'deny') {
            label.textContent = '🚫 Outils refusés';
            help.textContent = 'Les outils cochés seront bloqués. Tous les autres resteront accessibles.';
        } else {
            label.textContent = 'Outils';
            help.textContent = 'Aucune restriction — tous les outils sont accessibles.';
        }
    }
    const toolsList = document.getElementById('cpToolsList');
    if (toolsList) {
        toolsList.style.display = (mode === 'none') ? 'none' : '';
    }
}

/* ─── Path Rules dynamiques ─── */
function _renderPathRules() {
    const container = document.getElementById('cpPathRulesContainer');
    if (!container) return;
    container.innerHTML = '';
    _pathRuleCount = 0;
}

function addPathRule() {
    const container = document.getElementById('cpPathRulesContainer');
    if (!container) return;
    const idx = _pathRuleCount++;

    const ruleHtml = `<div class="path-rule-form" id="pathRule_${idx}">
        <div class="path-rule-form-header">
            <span style="font-weight:600;color:var(--accent);font-size:0.8rem">Règle #${idx + 1}</span>
            <button type="button" class="btn btn-ghost btn-sm" onclick="removePathRule(${idx})" style="padding:0.1rem 0.4rem">✕</button>
        </div>
        <div class="form-row">
            <div class="form-group">
                <label>Pattern vault <span class="help-icon" title="Pattern fnmatch pour le vault_id (ex: production-*, *, my-vault)">ⓘ</span></label>
                <input type="text" id="pr_vault_${idx}" placeholder="ex: production-* ou *" value="*">
            </div>
            <div class="form-group">
                <label>Permissions</label>
                <div class="checkbox-group">
                    <label><input type="checkbox" id="pr_perm_read_${idx}" checked> read</label>
                    <label><input type="checkbox" id="pr_perm_write_${idx}"> write</label>
                    <label><input type="checkbox" id="pr_perm_delete_${idx}"> delete</label>
                </div>
            </div>
        </div>
        <div class="form-group">
            <label>Chemins autorisés <span class="help-icon" title="Patterns fnmatch séparés par des virgules. Ex: shared/*, config/public/**&#10;Si vide = tous les chemins autorisés dans ce vault.">ⓘ</span></label>
            <input type="text" id="pr_paths_${idx}" placeholder="ex: shared/*, config/public/** (vide = tous)">
            <div class="help-text" style="margin-top:0.2rem">Patterns <code>fnmatch</code> : <code>*</code> = un niveau, <code>**</code> = récursif</div>
        </div>
    </div>`;

    container.insertAdjacentHTML('beforeend', ruleHtml);
}

function removePathRule(idx) {
    const el = document.getElementById(`pathRule_${idx}`);
    if (el) el.remove();
}

/* ─── Sauvegarder la policy ─── */
async function doCreatePolicy() {
    const policyId = document.getElementById('cpPolicyId').value.trim();
    if (!policyId) { alert('L\'identifiant de la policy est requis'); return; }

    const mode = document.getElementById('cpMode').value;
    const description = document.getElementById('cpDescription').value.trim();

    // Collecter les outils cochés
    const checkedTools = [];
    const checkboxes = document.querySelectorAll('#cpToolsList input[type="checkbox"]:checked');
    for (const cb of checkboxes) {
        checkedTools.push(cb.value);
    }

    const body = {
        policy_id: policyId,
        description: description,
        allowed_tools: mode === 'allow' ? checkedTools : [],
        denied_tools: mode === 'deny' ? checkedTools : [],
        path_rules: _collectPathRules(),
    };

    const data = await api('/policies', { method: 'POST', body: JSON.stringify(body) });
    closeModal('modalCreatePolicy');

    if (data.status === 'created') {
        _selectedPolicy = policyId;
        loadPolicies();
    } else {
        alert('Erreur : ' + (data.message || 'Échec de la création'));
    }
}

function _collectPathRules() {
    const rules = [];
    const container = document.getElementById('cpPathRulesContainer');
    if (!container) return rules;

    const ruleDivs = container.querySelectorAll('.path-rule-form');
    for (const div of ruleDivs) {
        const idx = div.id.replace('pathRule_', '');
        const vaultPattern = document.getElementById(`pr_vault_${idx}`)?.value.trim() || '*';
        const perms = [];
        if (document.getElementById(`pr_perm_read_${idx}`)?.checked) perms.push('read');
        if (document.getElementById(`pr_perm_write_${idx}`)?.checked) perms.push('write');
        if (document.getElementById(`pr_perm_delete_${idx}`)?.checked) perms.push('delete');

        const pathsStr = document.getElementById(`pr_paths_${idx}`)?.value.trim() || '';
        const allowedPaths = pathsStr ? pathsStr.split(',').map(s => s.trim()).filter(Boolean) : [];

        rules.push({
            vault_pattern: vaultPattern,
            permissions: perms,
            allowed_paths: allowedPaths,
        });
    }
    return rules;
}

/* ─── Supprimer une policy ─── */
async function deletePolicy(policyId) {
    if (!confirm(`Supprimer la policy "${policyId}" ? Les tokens utilisant cette policy ne seront plus restreints.`)) return;
    await api(`/policies/${policyId}`, { method: 'DELETE' });
    if (_selectedPolicy === policyId) {
        _selectedPolicy = null;
        const detail = document.getElementById('policyDetail');
        if (detail) detail.innerHTML = '';
    }
    loadPolicies();
}

/* ═══════════════════════════════════════════════════════════════════════
   Helpers pour le chargement des policies dans d'autres vues
   ═══════════════════════════════════════════════════════════════════════ */

async function loadPolicyOptions(selectId) {
    const select = document.getElementById(selectId);
    if (!select) return;

    // Garder la valeur actuelle
    const currentValue = select.value;

    let html = '<option value="">— Aucune policy —</option>';

    try {
        const data = await api('/policies');
        const policies = data.policies || [];
        for (const p of policies) {
            const desc = p.description ? ` (${p.description})` : '';
            html += `<option value="${esc(p.policy_id)}">${esc(p.policy_id)}${esc(desc)}</option>`;
        }
    } catch (e) {
        // Pas de policies disponibles
    }

    select.innerHTML = html;
    if (currentValue) select.value = currentValue;
}
