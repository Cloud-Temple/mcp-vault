/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — Vaults View (CRUD vaults + secrets)
   Formulaires dynamiques par type de secret
   ═══════════════════════════════════════════════════════════════════════ */

let _selectedVault = null;

/* ═══════════════════════════════════════════════════════════════════════
   Définition des types de secrets et leurs champs
   Miroir de vault/types.py — labels FR, placeholders, types d'input
   ═══════════════════════════════════════════════════════════════════════ */

const SECRET_TYPE_FIELDS = {
    login: {
        icon: '🔑', label: 'Identifiants',
        desc: 'Login + mot de passe + URL',
        fields: [
            { name: 'username', label: 'Nom d\'utilisateur', required: true, placeholder: 'admin@example.com' },
            { name: 'password', label: 'Mot de passe', required: true, inputType: 'password', canGenerate: true },
            { name: 'url', label: 'URL', placeholder: 'https://app.example.com' },
            { name: 'totp_secret', label: 'Secret TOTP', placeholder: 'JBSWY3DPEHPK3PXP' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    password: {
        icon: '🔒', label: 'Mot de passe',
        desc: 'Mot de passe simple',
        fields: [
            { name: 'password', label: 'Mot de passe', required: true, inputType: 'password', canGenerate: true },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    secure_note: {
        icon: '📝', label: 'Note sécurisée',
        desc: 'Texte libre chiffré',
        fields: [
            { name: 'title', label: 'Titre', placeholder: 'Ma note confidentielle' },
            { name: 'content', label: 'Contenu', required: true, inputType: 'textarea', placeholder: 'Texte libre chiffré…' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    api_key: {
        icon: '🔌', label: 'Clé API',
        desc: 'REST, GraphQL, services cloud',
        fields: [
            { name: 'key', label: 'Clé API', required: true, placeholder: 'sk-abc123…' },
            { name: 'secret', label: 'Secret', inputType: 'password', placeholder: 'Secret associé (optionnel)' },
            { name: 'endpoint', label: 'Endpoint', placeholder: 'https://api.example.com/v1' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    ssh_key: {
        icon: '🗝️', label: 'Clé SSH',
        desc: 'Paire de clés SSH',
        fields: [
            { name: 'private_key', label: 'Clé privée', required: true, inputType: 'textarea', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' },
            { name: 'public_key', label: 'Clé publique', inputType: 'textarea', placeholder: 'ssh-ed25519 AAAA…' },
            { name: 'passphrase', label: 'Passphrase', inputType: 'password' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    database: {
        icon: '🗄️', label: 'Base de données',
        desc: 'Connexion PostgreSQL, MySQL, etc.',
        fields: [
            { name: 'host', label: 'Hôte', required: true, placeholder: 'db.example.com' },
            { name: 'port', label: 'Port', placeholder: '5432', half: true },
            { name: 'database', label: 'Base de données', placeholder: 'mydb', half: true },
            { name: 'username', label: 'Utilisateur', required: true, placeholder: 'postgres' },
            { name: 'password', label: 'Mot de passe', required: true, inputType: 'password', canGenerate: true },
            { name: 'connection_string', label: 'Chaîne de connexion', placeholder: 'postgresql://user:pass@host:5432/db' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    server: {
        icon: '🖥️', label: 'Serveur',
        desc: 'Accès SSH, RDP, etc.',
        fields: [
            { name: 'host', label: 'Hôte', required: true, placeholder: '192.168.1.100' },
            { name: 'port', label: 'Port', placeholder: '22', half: true },
            { name: 'username', label: 'Utilisateur', required: true, placeholder: 'root' },
            { name: 'password', label: 'Mot de passe', inputType: 'password', canGenerate: true },
            { name: 'private_key', label: 'Clé privée SSH', inputType: 'textarea', placeholder: '-----BEGIN OPENSSH PRIVATE KEY-----' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    certificate: {
        icon: '📜', label: 'Certificat TLS/SSL',
        desc: 'Certificat + clé privée',
        fields: [
            { name: 'certificate', label: 'Certificat (PEM)', required: true, inputType: 'textarea', placeholder: '-----BEGIN CERTIFICATE-----' },
            { name: 'private_key', label: 'Clé privée (PEM)', required: true, inputType: 'textarea', placeholder: '-----BEGIN PRIVATE KEY-----' },
            { name: 'chain', label: 'Chaîne CA (intermédiaires)', inputType: 'textarea', placeholder: '-----BEGIN CERTIFICATE-----' },
            { name: 'expiry', label: 'Date d\'expiration', placeholder: '2027-12-31' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    env_file: {
        icon: '📄', label: 'Fichier .env',
        desc: 'Variables d\'environnement',
        fields: [
            { name: 'content', label: 'Contenu', required: true, inputType: 'textarea', placeholder: 'DB_HOST=localhost\nDB_PORT=5432\nSECRET_KEY=abc123' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    credit_card: {
        icon: '💳', label: 'Carte bancaire',
        desc: 'Numéro, expiration, CVV',
        fields: [
            { name: 'number', label: 'Numéro de carte', required: true, placeholder: '4111 1111 1111 1111' },
            { name: 'expiry', label: 'Expiration', required: true, placeholder: '12/28', half: true },
            { name: 'cvv', label: 'CVV', required: true, inputType: 'password', placeholder: '•••', half: true },
            { name: 'cardholder', label: 'Titulaire', placeholder: 'JEAN DUPONT' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    identity: {
        icon: '👤', label: 'Identité',
        desc: 'Nom, email, téléphone, adresse',
        fields: [
            { name: 'name', label: 'Nom complet', required: true, placeholder: 'Jean Dupont' },
            { name: 'email', label: 'Email', placeholder: 'jean@example.com', half: true },
            { name: 'phone', label: 'Téléphone', placeholder: '+33 6 12 34 56 78', half: true },
            { name: 'company', label: 'Entreprise', placeholder: 'Cloud Temple' },
            { name: 'address', label: 'Adresse', inputType: 'textarea', placeholder: '1 rue de la Paix\n75001 Paris' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    wifi: {
        icon: '📶', label: 'Réseau Wi-Fi',
        desc: 'SSID + mot de passe',
        fields: [
            { name: 'ssid', label: 'Nom du réseau (SSID)', required: true, placeholder: 'MonWifi-5G' },
            { name: 'password', label: 'Mot de passe Wi-Fi', required: true, inputType: 'password', canGenerate: true },
            { name: 'security_type', label: 'Type de sécurité', placeholder: 'WPA2-PSK' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    crypto_wallet: {
        icon: '₿', label: 'Wallet crypto',
        desc: 'Seed phrase, clé privée, adresse',
        fields: [
            { name: 'address', label: 'Adresse du wallet', placeholder: '0xAbC123… ou bc1q…' },
            { name: 'private_key', label: 'Clé privée', inputType: 'password' },
            { name: 'seed_phrase', label: 'Seed phrase (12/24 mots)', inputType: 'textarea', placeholder: 'abandon ability able about above absent…' },
            { name: 'notes', label: 'Notes', inputType: 'textarea' },
        ]
    },
    custom: {
        icon: '⚙️', label: 'Personnalisé',
        desc: 'Champs libres (JSON)',
        fields: null  // mode JSON libre
    }
};


/* ═══════════════════════════════════════════════════════════════════════
   Rendu dynamique des champs selon le type
   ═══════════════════════════════════════════════════════════════════════ */

function renderSecretFields(type) {
    const container = document.getElementById('wsFields');
    if (!container) return;

    const schema = SECRET_TYPE_FIELDS[type];

    // Type custom → textarea JSON
    if (!schema || !schema.fields) {
        container.innerHTML = `
            <div class="type-hint"><span class="type-hint-icon">⚙️</span> Champs libres — saisissez vos données en JSON</div>
            <div class="form-group">
                <label for="wsData">Données (JSON)</label>
                <textarea id="wsData" rows="6" class="mono-textarea">{\n  "key": "value"\n}</textarea>
            </div>`;
        return;
    }

    // Type structuré → champs dynamiques
    let html = `<div class="type-hint"><span class="type-hint-icon">${schema.icon}</span> ${schema.desc}</div>`;

    // Grouper les champs "half" en paires
    let i = 0;
    while (i < schema.fields.length) {
        const field = schema.fields[i];
        const next = (i + 1 < schema.fields.length) ? schema.fields[i + 1] : null;

        // Deux champs "half" côte à côte
        if (field.half && next && next.half) {
            html += '<div class="form-row">';
            html += _renderField(field);
            html += _renderField(next);
            html += '</div>';
            i += 2;
        } else {
            html += _renderField(field);
            i++;
        }
    }

    container.innerHTML = html;
}

function _renderField(field) {
    const req = field.required ? ' <span class="field-required">*</span>' : '';
    const id = `wsField_${field.name}`;
    const ph = field.placeholder || '';

    if (field.inputType === 'textarea') {
        return `<div class="form-group">
            <label for="${id}">${field.label}${req}</label>
            <textarea id="${id}" rows="3" placeholder="${ph}"${field.required ? ' required' : ''}></textarea>
        </div>`;
    }

    if (field.inputType === 'password') {
        return `<div class="form-group">
            <label for="${id}">${field.label}${req}</label>
            <div class="input-with-actions">
                <input type="password" id="${id}" placeholder="${ph || '••••••••'}"${field.required ? ' required' : ''}>
                <button type="button" class="btn-field-action" onclick="togglePasswordVisibility('${id}')" title="Afficher / masquer">👁️</button>
                ${field.canGenerate ? `<button type="button" class="btn-field-action btn-generate" onclick="generatePasswordFor('${id}')" title="Générer un mot de passe sécurisé (24 car.)">🎲</button>` : ''}
            </div>
        </div>`;
    }

    // Default: text input
    return `<div class="form-group">
        <label for="${id}">${field.label}${req}</label>
        <input type="text" id="${id}" placeholder="${ph}"${field.required ? ' required' : ''}>
    </div>`;
}


/* ═══════════════════════════════════════════════════════════════════════
   Actions sur les champs de mot de passe
   ═══════════════════════════════════════════════════════════════════════ */

function togglePasswordVisibility(fieldId) {
    const el = document.getElementById(fieldId);
    if (el) el.type = el.type === 'password' ? 'text' : 'password';
}

async function generatePasswordFor(fieldId) {
    const el = document.getElementById(fieldId);
    if (!el) return;

    // Feedback visuel : spinner
    const btn = el.parentElement.querySelector('.btn-generate');
    if (btn) { btn.textContent = '⏳'; btn.disabled = true; }

    try {
        const result = await api('/generate-password');
        if (result.password) {
            el.value = result.password;
            el.type = 'text';  // Montrer le mot de passe généré
            // Flash vert
            el.style.borderColor = 'var(--success)';
            el.style.boxShadow = '0 0 0 3px rgba(39,174,96,0.2)';
            setTimeout(() => { el.style.borderColor = ''; el.style.boxShadow = ''; }, 2000);
        }
    } catch (err) {
        // Fallback local si l'API échoue
        const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()_+-=';
        let pw = '';
        const arr = new Uint32Array(24);
        crypto.getRandomValues(arr);
        for (let i = 0; i < 24; i++) pw += chars[arr[i] % chars.length];
        el.value = pw;
        el.type = 'text';
    }

    if (btn) { btn.textContent = '🎲'; btn.disabled = false; }
}


/* ═══════════════════════════════════════════════════════════════════════
   Chargement de la vue Vaults
   ═══════════════════════════════════════════════════════════════════════ */

async function loadVaults() {
    const el = document.getElementById('page-vaults');
    const data = await api('/vaults');
    const vaults = data.vaults || [];

    let html = '<div class="flex-between" style="margin-bottom:1rem">';
    html += `<h2 style="color:var(--accent)">🗄️ Vaults (${vaults.length})</h2>`;
    if (canWrite()) html += `<button class="btn btn-primary" onclick="openModal('modalCreateVault')">+ Nouveau vault</button>`;
    html += '</div>';

    if (vaults.length === 0) {
        html += '<div class="empty-state">Aucun vault. Créez-en un pour commencer.</div>';
    } else {
        // Vue tableau pour mieux afficher les colonnes
        html += '<div class="card" style="padding:0;overflow-x:auto"><table>';
        html += '<thead><tr><th>Vault</th><th>Description</th><th>Secrets</th><th>Owner</th><th>Créé le</th></tr></thead><tbody>';
        for (const v of vaults) {
            const isOwner = v.created_by === STATE.clientName;
            const ownerBadge = v.created_by
                ? (isOwner
                    ? `<span class="badge badge-ok" title="Vous êtes le propriétaire">👤 ${esc(v.created_by)}</span>`
                    : `<span class="badge" style="background:rgba(52,152,219,0.15);color:#3498db" title="Vault partagé avec vous">👥 ${esc(v.created_by)}</span>`)
                : '<span style="color:var(--muted)">—</span>';

            html += `<tr style="cursor:pointer" onclick="selectVault('${esc(v.vault_id)}')">
                <td><strong style="color:var(--accent)">📁 ${esc(v.vault_id)}</strong></td>
                <td style="color:var(--text2);max-width:200px;overflow:hidden;text-overflow:ellipsis">${esc(v.description || '')}</td>
                <td><span class="badge badge-info">${v.secrets_count || 0}</span></td>
                <td>${ownerBadge}</td>
                <td style="color:var(--muted);font-size:0.75rem">${fmtDate(v.created_at)}</td>
            </tr>`;
        }
        html += '</tbody></table></div>';
    }

    html += '<div id="vaultDetail"></div>';
    el.innerHTML = html;

    // Reselect if was selected
    if (_selectedVault) selectVault(_selectedVault);
}

/* ─── Select vault → show detail ─── */
async function selectVault(vaultId) {
    _selectedVault = vaultId;
    const el = document.getElementById('vaultDetail');
    if (!el) return;
    el.innerHTML = '<div class="empty-state">Chargement…</div>';

    const data = await api(`/vaults/${vaultId}`);
    if (data.status === 'error') { el.innerHTML = `<div class="empty-state">Erreur : ${esc(data.message)}</div>`; return; }

    const keys = data.secret_keys || [];
    const roles = data.ssh_ca_roles || [];

    let html = `<div class="card mt-1">
        <div class="flex-between">
            <h2>📁 ${esc(vaultId)}</h2>
            <div style="display:flex;gap:0.4rem">`;
    if (canWrite()) html += `<button class="btn btn-ghost btn-sm" onclick="promptUpdateVault('${esc(vaultId)}')">✏️ Modifier</button>`;
    if (isAdmin()) html += `<button class="btn btn-danger btn-sm" onclick="promptDeleteVault('${esc(vaultId)}')">🗑️ Supprimer</button>`;
    html += `<button class="btn btn-ghost btn-sm" onclick="_selectedVault=null;document.getElementById('vaultDetail').innerHTML=''">✕</button>
            </div>
        </div>
        ${data.description ? `<p style="color:var(--text2);margin:0.5rem 0">${esc(data.description)}</p>` : ''}
        <table style="margin-bottom:0.8rem">
            <tr><td style="color:var(--muted);width:120px">Secrets</td><td>${data.secrets_count || 0}</td></tr>
            <tr><td style="color:var(--muted)">Créé par</td><td>${esc(data.created_by || '—')}</td></tr>
            <tr><td style="color:var(--muted)">Créé le</td><td>${fmtDate(data.created_at)}</td></tr>
            <tr><td style="color:var(--muted)">Modifié</td><td>${fmtDate(data.updated_at)}</td></tr>
            ${roles.length > 0 ? `<tr><td style="color:var(--muted)">SSH CA</td><td>${roles.map(r => `<span class="badge badge-info">${esc(r)}</span>`).join(' ')}</td></tr>` : ''}
        </table>`;

    // SSH CA section
    html += '<div class="flex-between mt-1"><h2>🔏 SSH Certificate Authority</h2>';
    if (canWrite()) html += `<div style="display:flex;gap:0.3rem">
        <button class="btn btn-ghost btn-sm" onclick="promptSshSetup('${esc(vaultId)}')">+ Ajouter un rôle</button>
        ${data.has_ssh_ca ? `<button class="btn btn-ghost btn-sm" onclick="showCaKey('${esc(vaultId)}')">🔑 Clé publique CA</button>` : ''}
        ${data.has_ssh_ca ? `<button class="btn btn-primary btn-sm" onclick="promptSshSign('${esc(vaultId)}')">✍️ Signer une clé</button>` : ''}
    </div>`;
    html += '</div>';

    if (roles.length > 0) {
        html += '<div id="sshRolesList">';
        for (const r of roles) {
            html += `<div class="secret-item" onclick="showRoleInfo('${esc(vaultId)}','${esc(r)}','ri_${esc(r)}')">
                <span>🔏</span><code>${esc(r)}</code>
                <span style="color:var(--muted);font-size:0.75rem;margin-left:auto">Cliquer pour détails</span>
            </div>
            <div id="ri_${esc(r)}" class="hidden"></div>`;
        }
        html += '</div>';
    } else {
        html += '<div class="empty-state" style="padding:0.8rem"><p>Aucun rôle SSH CA configuré.</p><p style="font-size:0.72rem;color:var(--muted)">Cliquez « + Ajouter un rôle » pour créer une CA et un premier rôle.</p></div>';
    }

    html += '<div id="sshCaKeyDisplay"></div>';

    // Secrets section
    html += '<div class="flex-between mt-1"><h2>🔐 Secrets</h2>';
    if (canWrite()) html += `<button class="btn btn-primary btn-sm" onclick="promptWriteSecret('${esc(vaultId)}')">+ Ajouter</button>`;
    html += '</div>';

    if (keys.length === 0) {
        html += '<div class="empty-state" style="padding:1rem">Aucun secret</div>';
    } else {
        html += '<div id="secretsList">';
        for (const k of keys) {
            const kid = esc(k).replace(/\//g, '_');
            html += `<div class="secret-item" onclick="toggleSecret('${esc(vaultId)}','${esc(k)}','sd_${kid}')">
                <span>🔑</span><code>${esc(k)}</code>
                ${isAdmin() ? `<button class="btn btn-danger btn-sm" style="margin-left:auto" onclick="event.stopPropagation();promptDeleteSecret('${esc(vaultId)}','${esc(k)}')">🗑️</button>` : ''}
            </div>
            <div id="sd_${kid}" class="hidden"></div>`;
        }
        html += '</div>';
    }

    html += '</div>';
    el.innerHTML = html;
}

/* ─── Toggle secret detail (read value) ─── */
async function toggleSecret(vaultId, secretPath, elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }

    el.innerHTML = '<div class="secret-detail">Chargement…</div>';
    el.classList.remove('hidden');

    const data = await api(`/vaults/${vaultId}/secrets/${secretPath}`);
    if (data.status !== 'ok') {
        el.innerHTML = `<div class="secret-detail" style="color:var(--danger)">Erreur : ${esc(data.message)}</div>`;
        return;
    }

    const secretData = data.data || {};
    const lines = Object.entries(secretData).map(([k, v]) => {
        const isHidden = k === 'password' || k === 'private_key' || k === 'secret' || k === 'cvv' || k === 'seed_phrase';
        return `<span style="color:var(--muted)">${esc(k)}</span>: <span style="color:${isHidden ? 'var(--warning)' : 'var(--text)'}">${esc(String(v))}</span>`;
    });

    el.innerHTML = `<div class="secret-detail">
        <div style="margin-bottom:0.4rem;font-size:0.7rem;color:var(--muted)">Version ${data.version} — ${fmtDate(data.created_time)}</div>
        ${lines.join('\n')}
    </div>`;
}

/* ─── Create vault ─── */
async function doCreateVault() {
    const vaultId = document.getElementById('cvVaultId').value.trim();
    const desc = document.getElementById('cvDescription').value.trim();
    if (!vaultId) return;

    const result = await api('/vaults', { method: 'POST', body: JSON.stringify({ vault_id: vaultId, description: desc }) });
    closeModal('modalCreateVault');

    if (result.status === 'created') {
        _selectedVault = vaultId;
        loadVaults();
    } else {
        alert(`Erreur : ${result.message || 'Échec création'}`);
    }
    document.getElementById('cvVaultId').value = '';
    document.getElementById('cvDescription').value = '';
}

/* ─── Update vault ─── */
function promptUpdateVault(vaultId) {
    const desc = prompt(`Nouvelle description pour "${vaultId}" :`);
    if (desc === null) return;
    api(`/vaults/${vaultId}`, { method: 'PUT', body: JSON.stringify({ description: desc }) })
        .then(() => selectVault(vaultId));
}

/* ─── Delete vault ─── */
function promptDeleteVault(vaultId) {
    if (!confirm(`⚠️ Supprimer le vault "${vaultId}" et TOUS ses secrets ? Cette action est irréversible.`)) return;
    api(`/vaults/${vaultId}`, { method: 'DELETE' }).then(() => {
        _selectedVault = null;
        loadVaults();
    });
}

/* ─── Write secret (ouvre la modal avec formulaire dynamique) ─── */
function promptWriteSecret(vaultId) {
    document.getElementById('wsVaultId').value = vaultId;
    document.getElementById('wsPath').value = '';
    document.getElementById('wsType').value = 'login';
    renderSecretFields('login');
    openModal('modalWriteSecret');
}

/* ─── Enregistrer le secret (collecte depuis champs dynamiques) ─── */
async function doWriteSecret() {
    const vaultId = document.getElementById('wsVaultId').value;
    const path = document.getElementById('wsPath').value.trim();
    const type = document.getElementById('wsType').value;

    if (!path) {
        alert('Le chemin est requis');
        document.getElementById('wsPath').focus();
        return;
    }

    let data;
    const schema = SECRET_TYPE_FIELDS[type];

    if (!schema || !schema.fields) {
        // Mode JSON libre (type custom)
        try {
            data = JSON.parse(document.getElementById('wsData').value);
        } catch {
            alert('JSON invalide dans les données');
            return;
        }
    } else {
        // Mode formulaire dynamique
        data = {};
        for (const field of schema.fields) {
            const el = document.getElementById(`wsField_${field.name}`);
            const val = el ? el.value.trim() : '';

            if (val) {
                data[field.name] = val;
            } else if (field.required) {
                alert(`Le champ « ${field.label} » est requis`);
                if (el) el.focus();
                return;
            }
        }

        if (Object.keys(data).length === 0) {
            alert('Remplissez au moins un champ');
            return;
        }
    }

    const result = await api(`/vaults/${vaultId}/secrets`, {
        method: 'POST',
        body: JSON.stringify({ path, type, data })
    });
    closeModal('modalWriteSecret');

    if (result.status === 'ok') {
        selectVault(vaultId);
    } else {
        alert(`Erreur : ${result.message || 'Échec écriture'}`);
    }
}

/* ─── Delete secret ─── */
function promptDeleteSecret(vaultId, path) {
    if (!confirm(`Supprimer le secret "${path}" ? Irréversible.`)) return;
    api(`/vaults/${vaultId}/secrets/${path}`, { method: 'DELETE' }).then(() => selectVault(vaultId));
}


/* ═══════════════════════════════════════════════════════════════════════
   SSH Certificate Authority — Setup, Sign, CA Key, Role Info
   ═══════════════════════════════════════════════════════════════════════ */

/* ─── SSH Setup ─── */
function promptSshSetup(vaultId) {
    document.getElementById('ssVaultId').value = vaultId;
    document.getElementById('ssRoleName').value = '';
    document.getElementById('ssDefaultUser').value = 'ubuntu';
    document.getElementById('ssTtl').value = '30m';
    document.getElementById('ssAllowedUsers').value = '*';
    openModal('modalSshSetup');
}

async function doSshSetup() {
    const vaultId = document.getElementById('ssVaultId').value;
    const roleName = document.getElementById('ssRoleName').value.trim();
    if (!roleName) { alert('Le nom du rôle est requis'); return; }

    const body = {
        role_name: roleName,
        default_user: document.getElementById('ssDefaultUser').value.trim() || 'ubuntu',
        ttl: document.getElementById('ssTtl').value.trim() || '30m',
        allowed_users: document.getElementById('ssAllowedUsers').value.trim() || '*',
    };

    const data = await api(`/vaults/${vaultId}/ssh/setup`, {
        method: 'POST', body: JSON.stringify(body)
    });
    closeModal('modalSshSetup');

    if (data.status === 'ok') {
        selectVault(vaultId);
    } else {
        alert('Erreur : ' + (data.message || 'Échec du setup SSH CA'));
    }
}

/* ─── SSH Sign Key ─── */
async function promptSshSign(vaultId) {
    document.getElementById('sgVaultId').value = vaultId;
    document.getElementById('sgPublicKey').value = '';
    document.getElementById('sgTtl').value = '30m';
    document.getElementById('sgResult').innerHTML = '';

    // Charger les rôles dans le select
    const rolesData = await api(`/vaults/${vaultId}/ssh/roles`);
    const select = document.getElementById('sgRoleName');
    select.innerHTML = '';
    for (const r of (rolesData.roles || [])) {
        const opt = document.createElement('option');
        opt.value = r;
        opt.textContent = r;
        select.appendChild(opt);
    }

    openModal('modalSshSign');
}

async function doSshSign() {
    const vaultId = document.getElementById('sgVaultId').value;
    const roleName = document.getElementById('sgRoleName').value;
    const publicKey = document.getElementById('sgPublicKey').value.trim();
    const ttl = document.getElementById('sgTtl').value.trim() || '30m';

    if (!publicKey) { alert('Collez votre clé publique SSH'); return; }
    if (!roleName) { alert('Sélectionnez un rôle SSH'); return; }

    const resultEl = document.getElementById('sgResult');
    resultEl.innerHTML = '<div class="empty-state">Signature en cours…</div>';

    const data = await api(`/vaults/${vaultId}/ssh/sign`, {
        method: 'POST', body: JSON.stringify({ role_name: roleName, public_key: publicKey, ttl: ttl })
    });

    if (data.status === 'ok') {
        resultEl.innerHTML = `<div class="card" style="border-color:var(--success);margin-top:0.8rem">
            <h2 style="color:var(--success)">✅ Certificat signé</h2>
            <p style="font-size:0.75rem;color:var(--text2)">Serial : ${esc(data.serial_number || '—')} — TTL : ${esc(data.ttl || ttl)}</p>
            <div class="token-display" style="border-color:var(--success)">
                <span id="signedKeyValue">${esc(data.signed_key || '')}</span>
                <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('signedKeyValue').textContent)">📋</button>
            </div>
            <div class="help-text">Sauvegardez ce certificat dans un fichier (ex: id_ed25519-cert.pub) et utilisez-le avec <code>ssh -i id_ed25519 -o CertificateFile=id_ed25519-cert.pub user@host</code></div>
        </div>`;
    } else {
        resultEl.innerHTML = `<div class="card" style="border-color:var(--danger);margin-top:0.8rem">
            <p style="color:var(--danger)">❌ Erreur : ${esc(data.message || 'Échec de la signature')}</p>
        </div>`;
    }
}

/* ─── SSH CA Public Key ─── */
async function showCaKey(vaultId) {
    const el = document.getElementById('sshCaKeyDisplay');
    if (!el) return;

    if (!el.classList.contains('hidden') && el.innerHTML) {
        el.innerHTML = '';
        return;
    }

    const data = await api(`/vaults/${vaultId}/ssh/ca-key`);
    if (data.status === 'ok') {
        el.innerHTML = `<div class="card mt-1" style="border-color:var(--accent)">
            <h2>🔑 Clé publique CA SSH</h2>
            <div class="token-display">
                <span id="caKeyValue">${esc(data.public_key || '')}</span>
                <button class="copy-btn" onclick="navigator.clipboard.writeText(document.getElementById('caKeyValue').textContent)">📋</button>
            </div>
            <div class="help-text">${esc(data.usage || 'Ajouter dans TrustedUserCAKeys sur les serveurs cibles')}</div>
        </div>`;
    } else {
        el.innerHTML = `<div class="card mt-1"><p style="color:var(--danger)">Erreur : ${esc(data.message)}</p></div>`;
    }
}

/* ─── SSH Role Info ─── */
async function showRoleInfo(vaultId, roleName, elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }

    el.innerHTML = '<div class="secret-detail">Chargement…</div>';
    el.classList.remove('hidden');

    const data = await api(`/vaults/${vaultId}/ssh/roles/${roleName}`);
    if (data.status !== 'ok') {
        el.innerHTML = `<div class="secret-detail" style="color:var(--danger)">Erreur : ${esc(data.message)}</div>`;
        return;
    }

    el.innerHTML = `<div class="secret-detail">
        <span style="color:var(--muted)">key_type</span>: <span>${esc(data.key_type)}</span>
        <span style="color:var(--muted)">ttl</span>: <span>${esc(data.ttl)}</span>
        <span style="color:var(--muted)">max_ttl</span>: <span>${esc(data.max_ttl)}</span>
        <span style="color:var(--muted)">default_user</span>: <span>${esc(data.default_user)}</span>
        <span style="color:var(--muted)">allowed_users</span>: <span>${esc(data.allowed_users)}</span>
        <span style="color:var(--muted)">user_certs</span>: <span>${data.allow_user_certificates ? '✅' : '❌'}</span>
        <span style="color:var(--muted)">host_certs</span>: <span>${data.allow_host_certificates ? '✅' : '❌'}</span>
    </div>`;
}
