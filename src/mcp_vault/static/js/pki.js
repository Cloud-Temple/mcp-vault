/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — PKI Certificate Authority
   ═══════════════════════════════════════════════════════════════════════ */

async function loadPki() {
    const page = document.getElementById('page-pki');
    page.innerHTML = '<div class="loading">Chargement PKI...</div>';

    const status = await api('/pki/status');

    if (status.status === 'not_initialized') {
        page.innerHTML = _renderPkiSetupPanel();
        return;
    }
    if (status.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur PKI : ${esc(status.message)}</div>`;
        return;
    }

    // Charger certs et rôles en parallèle
    const [certs, roles] = await Promise.all([
        api('/pki/certs'),
        api('/pki/roles'),
    ]);

    if (certs.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur inventaire : ${esc(certs.message)}</div>`;
        return;
    }
    if (roles.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur rôles ACME : ${esc(roles.message)}</div>`;
        return;
    }

    // Détails du rôle ACME principal (acme-servers)
    let roleDetail = null;
    if (roles.roles && roles.roles.length > 0) {
        const d = await api(`/pki/roles/${encodeURIComponent(roles.roles[0])}`);
        if (d.status === 'ok') roleDetail = d;
    }

    page.innerHTML = _renderPkiPage(status, certs, roles, roleDetail);
}

/* ─── Rendu page PKI initialisée ─── */
function _renderPkiPage(s, certs, roles, roleDetail) {
    const now = new Date();
    const rootExp = s.root_expires !== 'inconnu' ? new Date(s.root_expires) : null;
    const intExp  = s.int_expires  !== 'inconnu' ? new Date(s.int_expires)  : null;

    function expBadge(dt) {
        if (!dt) return '<span class="badge badge-warn">inconnu</span>';
        const days = Math.round((dt - now) / 86400000);
        const cls  = days < 30 ? 'badge-danger' : days < 90 ? 'badge-warn' : 'badge-ok';
        return `<span class="badge ${cls}">${fmtDate(dt.toISOString())} (J-${days})</span>`;
    }

    const certRows = (certs.certs || []).map(c => {
        const sans = (c.sans || []).join(', ') || '—';
        const exp  = c.not_after ? fmtDate(c.not_after) : '—';
        // SÉCURITÉ #128 : « actif » ne disait PAS « valide », il disait « non
        // révoqué » — un certificat EXPIRÉ s'affichait donc en badge VERT. Sur un
        // écran de sécurité, un libellé qui affirme autre chose que le fait peut
        // faire sauter un renouvellement. Trois états, la révocation d'abord
        // (elle prime : un certificat révoqué ET expiré reste « révoqué »).
        const notAfter = c.not_after ? new Date(c.not_after) : null;
        const perime   = notAfter && !isNaN(notAfter.getTime()) && notAfter <= now;
        const rev  = c.revoked
            ? '<span class="badge badge-danger">révoqué</span>'
            : perime
                ? '<span class="badge badge-danger">expiré</span>'
                : '<span class="badge badge-ok">valide</span>';
        // SÉCURITÉ : JSON.stringify évite le XSS onclick (esc() n'échappe pas les quotes simples)
        const revokeBtn = (!c.revoked && isAdmin())
            ? `<button class="btn btn-sm btn-danger" onclick="pkiRevoke(${JSON.stringify(c.serial)})">Révoquer</button>`
            : '';
        return `<tr>
            <td class="mono-small">${esc(c.serial)}</td>
            <td>${esc(sans)}</td>
            <td>${exp}</td>
            <td>${rev}</td>
            <td>${revokeBtn}</td>
        </tr>`;
    }).join('') || '<tr><td colspan="5" class="empty-row">Aucun certificat émis</td></tr>';

    const actions = isAdmin()
        ? `<div class="page-header-actions">
               <button class="btn btn-primary" onclick="openModal('modalPkiIssue')">Générer un certificat</button>
               <button class="btn btn-warn" onclick="pkiRotate()">Rotation intermédiaire</button>
           </div>`
        : '';

    return `
    <div class="page-header">
        <h2>PKI Certificate Authority</h2>
        ${actions}
    </div>

    <!-- Statut CA -->
    <div class="card-grid">
        <div class="card">
            <div class="card-label">CA Racine</div>
            <div class="card-value">${expBadge(rootExp)}</div>
            <div class="card-sub">SHA-256 : <code class="mono-tiny">${esc(s.root_fingerprint_sha256 || '—')}</code></div>
        </div>
        <div class="card">
            <div class="card-label">CA Intermédiaire</div>
            <div class="card-value">${expBadge(intExp)}</div>
        </div>
        <div class="card">
            <div class="card-label">Certificats émis</div>
            <div class="card-value card-value-big">${s.cert_count !== undefined ? s.cert_count : '—'}</div>
        </div>
        <div class="card">
            <div class="card-label">Serveur ACME</div>
            <div class="card-value">${s.acme_enabled
                ? '<span class="badge badge-ok">Actif</span>'
                : '<span class="badge badge-warn">Inactif</span>'}</div>
        </div>
        <div class="card">
            <div class="card-label">EAB (enrôlement)</div>
            <div class="card-value">${s.eab_required
                ? `<span class="badge badge-ok">Requis</span> <span class="help-text">${esc(s.eab_policy || '')}</span>`
                : `<span class="badge badge-warn">Non requis</span> <span class="help-text">${esc(s.eab_policy || '')}</span>`}</div>
        </div>
    </div>

    <!-- URLs de distribution -->
    <div class="section-title">URLs de distribution (publiques)</div>
    <div class="url-list">
        ${_urlRow('CA Racine PEM', s.root_pem_url)}
        ${_urlRow('Chaîne complète PEM', s.chain_pem_url)}
        ${_urlRow('CRL PEM', s.crl_url)}
        ${_urlRow('Directory ACME', s.acme_directory)}
    </div>

    <!-- Rôles ACME -->
    <div class="section-title">Rôle ACME — politique d'émission</div>
    ${_renderAcmeRoles(roles, roleDetail)}

    <!-- Inventaire certs -->
    <div class="section-title">Inventaire des certificats</div>
    <div class="table-wrapper">
        <table>
            <thead><tr>
                <th>Numéro de série</th><th>SANs</th><th>Expiration</th>
                <th>Statut</th><th>Action</th>
            </tr></thead>
            <tbody>${certRows}</tbody>
        </table>
    </div>`;
}

function _renderAcmeRoles(roles, detail) {
    if (!roles || roles.status === 'error' || !roles.roles || roles.roles.length === 0) {
        return '<div class="empty-state" style="padding:0.5rem">Aucun rôle ACME configuré</div>';
    }
    const roleList = roles.roles.map(r => `<code>${esc(r)}</code>`).join(', ');
    if (!detail) return `<div class="help-text">Rôles : ${roleList}</div>`;

    const domains = (detail.allowed_domains || []).join(', ') || '—';
    const flags = [
        detail.server_flag ? 'server' : null,
        detail.allow_subdomains ? 'subdomains' : null,
        detail.allow_wildcard_certificates ? 'wildcard' : null,
    ].filter(Boolean).join(', ') || '—';

    return `<div class="url-list" style="gap:0.3rem">
        <div class="url-row"><span class="url-label">Rôle actif</span><code class="url-value">${esc(detail.role_name)}</code></div>
        <div class="url-row"><span class="url-label">Domaines autorisés</span><code class="url-value">${esc(domains)}</code></div>
        <div class="url-row"><span class="url-label">TTL max</span><code class="url-value">${esc(detail.max_ttl || '—')}</code></div>
        <div class="url-row"><span class="url-label">Flags</span><code class="url-value">${esc(flags)}</code></div>
        <div class="url-row"><span class="url-label">IP SANs</span><code class="url-value">${detail.allow_ip_sans ? '✅ autorisés' : '❌ refusés'}</code></div>
        <div class="url-row"><span class="url-label">Localhost</span><code class="url-value">${detail.allow_localhost ? '✅ autorisé' : '❌ refusé'}</code></div>
    </div>`;
}

function _urlRow(label, url) {
    if (!url) return '';
    return `<div class="url-row">
        <span class="url-label">${esc(label)}</span>
        <code class="url-value">${esc(url)}</code>
        <button class="btn-copy" onclick="navigator.clipboard.writeText(${JSON.stringify(url)})" title="Copier">⎘</button>
    </div>`;
}

/* ─── Rendu panneau setup ─── */
function _renderPkiSetupPanel() {
    return `
    <div class="page-header"><h2>PKI Certificate Authority</h2></div>
    <div class="empty-state">
        <p>La PKI interne n'est pas encore initialisée.</p>
        <p>Une fois configurée, les WAF Caddy pourront obtenir leurs certificats TLS via ACME.</p>
        ${isAdmin() ? '<button class="btn btn-primary" onclick="openModal(\'modalPkiSetup\')">Initialiser la PKI</button>' : '<p class="help-text">Contactez un administrateur pour initialiser la PKI.</p>'}
    </div>`;
}

/* ─── Actions PKI ─── */
async function pkiRevoke(serial) {
    if (!confirm(`Révoquer le certificat ${serial} ?`)) return;
    const result = await api(`/pki/certs/${encodeURIComponent(serial)}/revoke`, { method: 'POST', body: '{}' });
    if (result.status === 'ok') {
        loadPki();
    } else {
        _pkiShowError('Erreur révocation : ' + (result.message || 'échec'));
    }
}

async function pkiRotate() {
    if (!confirm('Effectuer une rotation de la CA intermédiaire ? (les anciens certs restent valides)')) return;
    const result = await api('/pki/ca/rotate', {
        method: 'POST',
        body: JSON.stringify({ keep_old_issuer: true, overlap_ttl: '48h' }),
    });
    if (result.status === 'ok') {
        _pkiShowError('Rotation effectuée — nouvel issuer : ' + (result.new_issuer_id || '?'), 'info');
        loadPki();
    } else {
        _pkiShowError('Erreur rotation : ' + (result.message || '—'));
    }
}

function _pkiShowError(message, type = 'error') {
    const page = document.getElementById('page-pki');
    const div = document.createElement('div');
    div.className = type === 'info' ? 'success-banner' : 'error-banner';
    div.textContent = message;  // textContent = safe, pas de XSS
    page.prepend(div);
    setTimeout(() => div.remove(), 6000);
}

async function doPkiSetup() {
    const labMode  = document.getElementById('pkiLabMode').value === 'true';
    const domains  = document.getElementById('pkiDomains').value.trim();
    const leafTtl  = document.getElementById('pkiLeafTtl').value.trim() || '720h';

    if (!domains) { alert('Domaines autorisés requis'); return; }

    const btn = document.querySelector('#modalPkiSetup .btn-primary');
    btn.disabled = true;
    btn.textContent = 'Initialisation...';

    const result = await api('/pki/setup', {
        method: 'POST',
        body: JSON.stringify({ lab_mode: labMode, allowed_domains: domains, leaf_ttl: leafTtl }),
    });

    btn.disabled = false;
    btn.textContent = 'Initialiser';

    if (result.status === 'ok') {
        closeModal('modalPkiSetup');
        loadPki();
    } else {
        alert('Erreur : ' + (result.message || '—'));
    }
}

/* ─── Génération de certificat (émission manuelle) ─── */
async function doPkiIssue() {
    const cn       = document.getElementById('pkiIssueCn').value.trim();
    const ttl      = document.getElementById('pkiIssueTtl').value.trim() || '720h';
    const altNames = document.getElementById('pkiIssueAltNames').value.trim();
    const ipSans   = document.getElementById('pkiIssueIpSans').value.trim();

    if (!cn) { alert('Common Name requis'); return; }

    const btn = document.querySelector('#modalPkiIssue .btn-primary');
    btn.disabled = true;
    btn.textContent = 'Émission...';

    const result = await api('/pki/issue', {
        method: 'POST',
        body: JSON.stringify({ common_name: cn, ttl, alt_names: altNames, ip_sans: ipSans }),
    });

    btn.disabled = false;
    btn.textContent = 'Générer';

    if (result.status === 'ok') {
        closeModal('modalPkiIssue');
        _pkiShowIssuedCert(result);
        loadPki();
    } else {
        alert('Erreur : ' + (result.message || '—'));
    }
}

/* Affiche le cert émis + clé privée UNE FOIS — pas de copie automatique
   (la clé privée ne touche jamais le presse-papier sans action explicite). */
function _pkiShowIssuedCert(result) {
    const ov = document.createElement('div');
    ov.className = 'modal-overlay active';
    // textContent uniquement pour les blocs PEM → aucun risque XSS
    const cn = result.common_name || '?';
    const serial = result.serial_number || '?';
    const exp = result.expiration || '?';
    ov.innerHTML = `
        <div class="modal modal-lg">
            <h2>Certificat émis — ${esc(cn)}</h2>
            <div class="success-banner">Serial : ${esc(serial)} — expire : ${esc(String(exp))}</div>
            <div class="error-banner">⚠️ Clé privée affichée une seule fois. Copiez-la et stockez-la maintenant.
                Elle n'est ni stockée côté serveur, ni récupérable ensuite.</div>
            <label>Clé privée</label>
            <textarea class="mono-textarea" rows="7" readonly id="_issuedKey"></textarea>
            <label>Certificat</label>
            <textarea class="mono-textarea" rows="6" readonly id="_issuedCert"></textarea>
            <label>Chaîne CA</label>
            <textarea class="mono-textarea" rows="4" readonly id="_issuedChain"></textarea>
            <div class="modal-actions">
                <button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">Fermer</button>
            </div>
        </div>`;
    document.body.appendChild(ov);
    // Injecter le PEM via .value (jamais innerHTML) — pas d'exécution, pas de clipboard auto
    ov.querySelector('#_issuedKey').value = result.private_key || '';
    ov.querySelector('#_issuedCert').value = result.certificate || '';
    ov.querySelector('#_issuedChain').value = result.ca_chain || '';
}
