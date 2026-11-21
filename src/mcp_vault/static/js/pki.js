/* ═══════════════════════════════════════════════════════════════════════
   MCP Vault Admin — PKI Certificate Authority
   ═══════════════════════════════════════════════════════════════════════

   SÉCURITÉ (#217) : aucune valeur venant du serveur n'est placée dans un
   attribut HTML. `esc()` n'échappe pas les guillemets : une URL ou un serial
   inséré dans `onclick="…"` pouvait créer un attribut d'événement. Les boutons
   ne portent donc que des indices ou des clés FIXES ; la valeur est lue dans
   `_pki` (état de la page), jamais dans le HTML. Les PEM passent par `.value`.
*/

const PKI_PAGE = 200;
const PKI_ACME_ROLE = 'acme-servers';
const PKI_TTL_PATTERN = /^\d{1,6}[smhd]$/;

/* État de la page : ce que les boutons relisent (jamais le HTML). */
const _pki = { status: null, certs: [], offset: 0, total: 0, roles: [], urls: {}, setupMode: 'init', replayRef: null };

async function loadPki(offset) {
    const page = document.getElementById('page-pki');
    page.innerHTML = '<div class="loading">Chargement PKI...</div>';
    _pki.offset = Number.isInteger(offset) && offset >= 0 ? offset : 0;

    const status = await api('/pki/status');
    _pki.status = status;

    if (status.status === 'not_initialized') {
        page.innerHTML = _renderPkiSetupPanel();
        return;
    }
    if (status.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur PKI : ${esc(status.message)}</div>`;
        return;
    }

    const [certs, roles] = await Promise.all([
        api(`/pki/certs?limit=${PKI_PAGE}&offset=${_pki.offset}`),
        api('/pki/roles'),
    ]);
    if (certs.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur inventaire : ${esc(certs.message)}</div>`;
        return;
    }
    if (roles.status === 'error') {
        page.innerHTML = `<div class="error-banner">Erreur rôles : ${esc(roles.message)}</div>`;
        return;
    }

    // Tous les rôles, ACME ouvert ou fermé (#217) : détail de chacun.
    const names = Array.isArray(roles.roles) ? roles.roles : [];
    const details = await Promise.all(names.map(n => api(`/pki/roles/${encodeURIComponent(n)}`)));
    _pki.roles = names.map((name, i) => ({ name, detail: details[i] && details[i].status === 'ok' ? details[i] : null }));
    _pki.certs = Array.isArray(certs.certs) ? certs.certs : [];
    _pki.total = Number.isInteger(certs.total) ? certs.total : _pki.certs.length;
    _pki.urls = { root: status.root_pem_url, chain: status.chain_pem_url, crl: status.crl_url, acme: status.acme_directory };

    page.innerHTML = _renderPkiPage(status);
}

/* ─── Fonctions pures (testées sous Node) ─── */

/* Seuils d'alerte (jours) : les autorités se renouvellent en semaines, la CRL
   se régénère toute seule et ne doit jamais approcher son échéance. */
const PKI_SEUILS_AUTORITE = { warn: 90, danger: 30 };
const PKI_SEUILS_CRL = { warn: 3, danger: 1 };

/* Badge d'échéance : `now` injectable pour les tests. */
function expiryBadgeState(iso, now, seuils) {
    const s = seuils || PKI_SEUILS_AUTORITE;
    if (!iso) return { cls: 'badge-warn', label: 'inconnue' };
    const dt = new Date(iso);
    if (isNaN(dt.getTime())) return { cls: 'badge-warn', label: 'inconnue' };
    const ms = dt - (now || new Date());
    if (ms <= 0) return { cls: 'badge-danger', label: 'expirée' };
    const hours = Math.floor(ms / 3600000);
    const days = Math.floor(hours / 24);
    const cls = days < s.danger ? 'badge-danger' : days < s.warn ? 'badge-warn' : 'badge-ok';
    return { cls, label: days >= 1 ? `J-${days}` : `${hours} h` };
}

/* Durée en secondes (OpenBao) → plus grande unité EXACTE dont le coefficient
   tient en 6 chiffres (format accepté par le setup) ; sinon '' (à saisir). */
function ttlFromSeconds(value) {
    if (typeof value === 'string' && PKI_TTL_PATTERN.test(value.trim())) return value.trim();
    const n = typeof value === 'number' ? value : (/^\d+$/.test(String(value || '')) ? Number(value) : NaN);
    if (!Number.isSafeInteger(n) || n <= 0) return '';
    for (const [unit, size] of [['d', 86400], ['h', 3600], ['m', 60], ['s', 1]]) {
        if (n % size === 0 && n / size <= 999999) return `${n / size}${unit}`;
    }
    return '';
}

/* Mode d'enrôlement déductible de la politique EAB lue ; null = non déductible. */
function labModeFromEab(eabPolicy) {
    if (eabPolicy === 'not-required') return true;
    if (eabPolicy === 'new-account-required') return false;
    return null;
}

/* Corps EXACT de POST /pki/setup, ou { error }. Aucun défaut d'enrôlement :
   installer ou rejouer une AC ne se devine pas. */
function pkiSetupBody(form) {
    if (form.labMode !== 'true' && form.labMode !== 'false') {
        return { error: "Choisissez le mode d'enrôlement ACME." };
    }
    const acme = form.acme !== 'false';
    const domains = String(form.domains || '').split(',').map(d => d.trim()).filter(Boolean);
    if (acme && domains.length === 0) return { error: 'Domaines autorisés requis quand ACME est actif.' };
    const leaf = String(form.leafTtl || '').trim();
    // Rejeu avec ACME actif : la durée réelle n'a pas pu être lue → saisie
    // obligatoire, jamais le défaut historique imposé en silence.
    if (acme && !leaf && form.requireLeafTtl) {
        return { error: 'Durée maximale des certificats ACME requise : la valeur actuelle n\'a pas pu être lue.' };
    }
    const body = {
        lab_mode: form.labMode === 'true',
        acme,
        allowed_domains: acme ? domains : [],
        leaf_ttl: leaf || '720h',
    };
    for (const [key, val] of [['root_ttl', form.rootTtl], ['int_ttl', form.intTtl]]) {
        const v = String(val || '').trim();
        if (v) body[key] = v;
    }
    return { body };
}

/* Valeurs lues à partir de l'état de la PKI, pour pré-remplir le rejeu. */
function pkiReplayReference(status, roles) {
    const acme = !!status.acme_enabled;
    const role = (roles || []).find(r => r.name === PKI_ACME_ROLE);
    const detail = role && role.detail;
    let domains = detail ? detail.allowed_domains : [];
    if (typeof domains === 'string') domains = domains.split(',');
    return {
        acme,
        labMode: acme ? labModeFromEab(status.eab_policy) : null,
        domains: acme ? (domains || []).map(d => String(d).trim()).filter(Boolean) : [],
        leafTtl: acme && detail ? ttlFromSeconds(detail.max_ttl) : '',
    };
}

/* Changements visibles par rapport à l'état lu (affichés avant confirmation). */
function pkiReplayChanges(ref, body) {
    const changes = [];
    if (ref.acme !== body.acme) {
        changes.push(body.acme ? 'ACME sera OUVERT (actuellement fermé).' : 'ACME sera FERMÉ (actuellement ouvert).');
    }
    if (body.acme) {
        const eab = body.lab_mode ? 'enrôlement LIBRE (sans invitation)' : 'enrôlement sur INVITATION (EAB)';
        if (ref.labMode === null || ref.labMode !== body.lab_mode) {
            changes.push(`Enrôlement des nouveaux clients ACME : ${eab}` +
                         (ref.labMode === null ? ' (réglage actuel non déterminé).' : ' — CHANGEMENT.'));
        }
        const before = [...ref.domains].sort().join(', ');
        const after = [...body.allowed_domains].sort().join(', ');
        if (before !== after) changes.push(`Domaines ACME : ${before || '(aucun)'} → ${after}`);
        if (ref.leafTtl !== body.leaf_ttl) {
            changes.push(`Durée max des certificats ACME : ${ref.leafTtl || '(inconnue)'} → ${body.leaf_ttl}`);
        }
    }
    if (body.root_ttl) changes.push(`Plafond de l'autorité racine : ${body.root_ttl}`);
    if (body.int_ttl) changes.push(`Plafond de l'autorité intermédiaire : ${body.int_ttl}`);
    return changes;
}

const PKI_REPLAY_EXPLANATION =
    'Rejouer la configuration de la PKI\n\n' +
    'CONSERVÉ : autorité racine, autorité intermédiaire et tous les certificats déjà émis ' +
    '(ils restent valides ; les clients n\'ont rien à changer).\n\n' +
    'RÉÉCRIT avec les valeurs du formulaire : activation d\'ACME, enrôlement des nouveaux clients ACME, ' +
    'domaines et durée maximale des certificats ACME, adresses de publication, configuration ' +
    'de la liste de révocation (CRL, renouvelée automatiquement).\n\n' +
    'ATTENTION : un réglage de la PKI modifié à la main en dehors de MCP Vault ' +
    'reviendrait à sa valeur standard.';

/* Corps EXACT de POST /pki/ca/rotate. */
function pkiRotateBody(intTtl) {
    const body = { keep_old_issuer: true, overlap_ttl: '48h' };
    const v = String(intTtl || '').trim();
    if (v) body.int_ttl = v;
    return body;
}

/* ─── Rendu page PKI initialisée ─── */
function _renderPkiPage(s) {
    const now = new Date();
    function badge(iso, seuils) {
        const st = expiryBadgeState(iso, now, seuils);
        const date = iso && !isNaN(new Date(iso).getTime()) ? fmtDate(new Date(iso).toISOString()) + ' ' : '';
        return `<span class="badge ${st.cls}">${esc(date)}(${esc(st.label)})</span>`;
    }
    const knownDate = v => (v && v !== 'inconnu') ? v : null;

    const certRows = _pki.certs.map((c, i) => {
        const sans = (c.sans || []).join(', ') || '—';
        const exp  = c.not_after ? fmtDate(c.not_after) : '—';
        // SÉCURITÉ #128 : trois états, la révocation d'abord.
        const notAfter = c.not_after ? new Date(c.not_after) : null;
        const perime   = notAfter && !isNaN(notAfter.getTime()) && notAfter <= now;
        const rev = c.revoked
            ? '<span class="badge badge-danger">révoqué</span>'
            : perime ? '<span class="badge badge-danger">expiré</span>'
                     : '<span class="badge badge-ok">valide</span>';
        // Indice généré ici, jamais une donnée serveur dans l'attribut.
        const revokeBtn = (!c.revoked && isAdmin())
            ? `<button class="btn btn-sm btn-danger" onclick="pkiRevokeAt(${i})">Révoquer</button>` : '';
        return `<tr><td class="mono-small">${esc(c.serial)}</td><td>${esc(sans)}</td>
            <td>${esc(exp)}</td><td>${rev}</td><td>${revokeBtn}</td></tr>`;
    }).join('') || '<tr><td colspan="5" class="empty-row">Aucun certificat émis</td></tr>';

    const first = _pki.total ? _pki.offset + 1 : 0;
    const last = _pki.offset + _pki.certs.length;
    const pager = `<div class="help-text">Certificats ${first}–${last} sur ${_pki.total}
        ${_pki.offset > 0 ? '<button class="btn btn-sm btn-ghost" onclick="pkiPage(-1)">← Précédents</button>' : ''}
        ${last < _pki.total ? '<button class="btn btn-sm btn-ghost" onclick="pkiPage(1)">Suivants →</button>' : ''}</div>`;

    const actions = isAdmin()
        ? `<div class="page-header-actions">
               <button class="btn btn-primary" onclick="openModal('modalPkiIssue')">Générer un certificat</button>
               ${s.csr_domain ? '<button class="btn btn-primary" onclick="openPkiSignCsr()">Signer une CSR</button>' : ''}
               <button class="btn btn-warn" onclick="openPkiRotate()">Rotation intermédiaire</button>
               <button class="btn btn-ghost" onclick="openPkiReplay()">Rejouer la configuration</button>
           </div>`
        : '';

    return `
    <div class="page-header"><h2>PKI Certificate Authority</h2>${actions}</div>

    <div class="card-grid">
        <div class="card"><div class="card-label">CA Racine</div>
            <div class="card-value">${badge(knownDate(s.root_expires))}</div>
            <div class="card-sub">SHA-256 : <code class="mono-tiny">${esc(s.root_fingerprint_sha256 || '—')}</code></div></div>
        <div class="card"><div class="card-label">CA Intermédiaire</div>
            <div class="card-value">${badge(knownDate(s.int_expires))}</div></div>
        <div class="card"><div class="card-label">Liste de révocation (CRL)</div>
            <div class="card-value" data-crl>${s.crl_next_update ? badge(s.crl_next_update, PKI_SEUILS_CRL) : '<span class="badge badge-danger">illisible</span>'}</div>
            <div class="card-sub">Prochaine mise à jour ; renouvelée automatiquement avant échéance.</div></div>
        <div class="card"><div class="card-label">Certificats émis</div>
            <div class="card-value card-value-big">${s.cert_count !== undefined ? esc(String(s.cert_count)) : '—'}</div></div>
        <div class="card"><div class="card-label">Serveur ACME</div>
            <div class="card-value">${s.acme_enabled ? '<span class="badge badge-ok">Actif</span>' : '<span class="badge badge-warn">Fermé</span>'}</div></div>
        <div class="card"><div class="card-label">EAB (enrôlement)</div>
            <div class="card-value">${!s.acme_enabled ? 'Sans objet' : s.eab_required
                ? `<span class="badge badge-ok">Sur invitation</span> <span class="help-text">${esc(s.eab_policy || '')}</span>`
                : `<span class="badge badge-warn">Libre</span> <span class="help-text">${esc(s.eab_policy || '')}</span>`}</div></div>
        <div class="card"><div class="card-label">Signature de CSR</div>
            <div class="card-value">${s.csr_domain
                ? `<code>${esc(s.csr_domain)}</code> <span class="help-text">${esc(s.csr_ttl || '')}</span>`
                : '<span class="help-text">désactivée</span>'}</div></div>
    </div>

    <div class="section-title">URLs de distribution (publiques)</div>
    <div class="url-list">
        ${_urlRow('CA Racine PEM', 'root')}${_urlRow('Chaîne complète PEM', 'chain')}
        ${_urlRow('CRL PEM', 'crl')}${_urlRow('Directory ACME', 'acme')}
    </div>

    <div class="section-title">Rôles d'émission</div>
    ${_renderRoles()}

    <div class="section-title">Inventaire des certificats</div>
    <div class="table-wrapper"><table>
        <thead><tr><th>Numéro de série</th><th>SANs</th><th>Expiration</th><th>Statut</th><th>Action</th></tr></thead>
        <tbody>${certRows}</tbody></table></div>
    ${pager}`;
}

function _renderRoles() {
    if (_pki.roles.length === 0) return '<div class="empty-state" style="padding:0.5rem">Aucun rôle configuré</div>';
    return _pki.roles.map(({ name, detail }) => {
        if (!detail) return `<div class="help-text">Rôle <code>${esc(name)}</code> : détail illisible</div>`;
        let domains = detail.allowed_domains || [];
        if (typeof domains === 'string') domains = domains.split(',');
        const flags = [detail.server_flag ? 'server' : null, detail.allow_subdomains ? 'subdomains' : null,
                       detail.allow_wildcard_certificates ? 'wildcard' : null].filter(Boolean).join(', ') || '—';
        return `<div class="url-list" style="gap:0.3rem;margin-bottom:0.8rem">
            <div class="url-row"><span class="url-label">Rôle</span><code class="url-value">${esc(name)}</code></div>
            <div class="url-row"><span class="url-label">Domaines autorisés</span><code class="url-value">${esc(domains.join(', ') || '—')}</code></div>
            <div class="url-row"><span class="url-label">TTL max</span><code class="url-value">${esc(ttlFromSeconds(detail.max_ttl) || String(detail.max_ttl || '—'))}</code></div>
            <div class="url-row"><span class="url-label">Flags</span><code class="url-value">${esc(flags)}</code></div>
            <div class="url-row"><span class="url-label">IP SANs</span><code class="url-value">${detail.allow_ip_sans ? '✅ autorisés' : '❌ refusés'}</code></div>
        </div>`;
    }).join('');
}

/* Clé FIXE dans l'attribut ; l'URL est relue dans `_pki.urls`. */
function _urlRow(label, key) {
    const url = _pki.urls[key];
    if (!url) return '';
    return `<div class="url-row"><span class="url-label">${esc(label)}</span>
        <code class="url-value">${esc(url)}</code>
        <button class="btn-copy" onclick="pkiCopyUrl('${key}')" title="Copier">⎘</button></div>`;
}

function pkiCopyUrl(key) {
    const url = _pki.urls[key];
    if (url) navigator.clipboard.writeText(url);
}

function pkiPage(direction) {
    const next = _pki.offset + direction * PKI_PAGE;
    loadPki(Math.max(0, next));
}

/* ─── Rendu panneau setup (PKI non initialisée) ─── */
function _renderPkiSetupPanel() {
    return `
    <div class="page-header"><h2>PKI Certificate Authority</h2></div>
    <div class="empty-state">
        <p>La PKI interne n'est pas encore initialisée.</p>
        ${isAdmin() ? '<button class="btn btn-primary" onclick="openPkiSetup()">Initialiser la PKI</button>'
                    : '<p class="help-text">Contactez un administrateur pour initialiser la PKI.</p>'}
    </div>`;
}

/* ─── Formulaire setup : initialisation et rejeu ─── */
function _setField(id, value) { document.getElementById(id).value = value; }
function _field(id) { return document.getElementById(id).value; }

function openPkiSetup() {
    _pki.setupMode = 'init';
    _pki.replayRef = null;
    document.getElementById('pkiSetupTitle').textContent = 'Initialiser la PKI interne';
    document.getElementById('pkiSetupReplayNotice').textContent = '';
    _setField('pkiLabMode', ''); _setField('pkiAcme', 'true'); _setField('pkiDomains', '');
    _setField('pkiLeafTtl', '720h'); _setField('pkiRootTtl', ''); _setField('pkiIntTtl', '');
    openModal('modalPkiSetup');
}

function openPkiReplay() {
    const ref = pkiReplayReference(_pki.status || {}, _pki.roles);
    _pki.setupMode = 'replay';
    _pki.replayRef = ref;
    document.getElementById('pkiSetupTitle').textContent = 'Rejouer la configuration de la PKI';
    document.getElementById('pkiSetupReplayNotice').textContent = PKI_REPLAY_EXPLANATION +
        (ref.acme && ref.labMode === null
            ? "\n\nLe mode d'enrôlement actuel n'a pas pu être lu : choisissez-le explicitement." : '');
    _setField('pkiLabMode', ref.labMode === null ? '' : String(ref.labMode));
    _setField('pkiAcme', String(ref.acme));
    _setField('pkiDomains', ref.domains.join(', '));
    _setField('pkiLeafTtl', ref.leafTtl);
    _setField('pkiRootTtl', ''); _setField('pkiIntTtl', '');
    openModal('modalPkiSetup');
}

async function doPkiSetup() {
    const form = { labMode: _field('pkiLabMode'), acme: _field('pkiAcme'), domains: _field('pkiDomains'),
                   leafTtl: _field('pkiLeafTtl'), rootTtl: _field('pkiRootTtl'), intTtl: _field('pkiIntTtl'),
                   requireLeafTtl: _pki.setupMode === 'replay' };
    const built = pkiSetupBody(form);
    if (built.error) { alert(built.error); return; }

    if (_pki.setupMode === 'replay') {
        const changes = pkiReplayChanges(_pki.replayRef, built.body);
        const message = PKI_REPLAY_EXPLANATION + '\n\n' + (changes.length
            ? 'CHANGEMENTS par rapport à la configuration actuelle :\n- ' + changes.join('\n- ')
            : 'Aucun changement par rapport aux réglages lus.') + '\n\nConfirmer ?';
        if (!confirm(message)) return;
    }

    const result = await api('/pki/setup', { method: 'POST', body: JSON.stringify(built.body) });
    if (result.status === 'ok') {
        closeModal('modalPkiSetup');
        loadPki();
    } else {
        alert('Erreur : ' + (result.message || '—'));
    }
}

/* ─── Actions PKI ─── */
async function pkiRevokeAt(index) {
    const cert = _pki.certs[index];
    if (!cert || cert.revoked) return;
    if (!confirm(`Révoquer le certificat ${cert.serial} ?`)) return;
    const result = await api(`/pki/certs/${encodeURIComponent(cert.serial)}/revoke`, { method: 'POST', body: '{}' });
    if (result.status === 'ok') loadPki(_pki.offset);
    else _pkiShowError('Erreur révocation : ' + (result.message || 'échec'));
}

function openPkiRotate() {
    _setField('pkiRotateIntTtl', '');
    openModal('modalPkiRotate');
}

async function doPkiRotate() {
    const result = await api('/pki/ca/rotate', { method: 'POST', body: JSON.stringify(pkiRotateBody(_field('pkiRotateIntTtl'))) });
    if (result.status === 'ok') {
        closeModal('modalPkiRotate');
        _pkiShowError('Rotation effectuée — nouvel émetteur : ' + (result.new_issuer_id || '?'), 'info');
        loadPki();
    } else {
        _pkiShowError('Erreur rotation : ' + (result.message || '—'));
    }
}

function openPkiSignCsr() {
    _setField('pkiSignCsrPem', '');
    document.getElementById('pkiSignCsrDomain').textContent =
        (_pki.status && _pki.status.csr_domain) ? _pki.status.csr_domain : '—';
    openModal('modalPkiSignCsr');
}

async function doPkiSignCsr() {
    const csr = _field('pkiSignCsrPem').trim();
    if (!csr) { alert('Collez la CSR (PEM).'); return; }
    const result = await api('/pki/sign-csr', { method: 'POST', body: JSON.stringify({ csr }) });
    if (result.status === 'ok') {
        closeModal('modalPkiSignCsr');
        _pkiShowSignedCsr(result);
        loadPki(_pki.offset);
    } else {
        alert('Signature refusée : ' + (result.message || '—'));
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

/* Fenêtre de résultat : PEM injectés par `.value`, jamais par innerHTML. */
function _pkiResultOverlay(title, banners, fields) {
    const ov = document.createElement('div');
    ov.className = 'modal-overlay active';
    ov.innerHTML = `<div class="modal modal-lg"><h2 data-titre></h2>
        ${banners.map(b => `<div class="${b[0]}" data-banniere></div>`).join('')}
        ${fields.map(() => '<label data-libelle></label><textarea class="mono-textarea" rows="6" readonly data-pem></textarea>').join('')}
        <div class="modal-actions"><button class="btn btn-ghost" onclick="this.closest('.modal-overlay').remove()">Fermer</button></div></div>`;
    document.body.appendChild(ov);
    ov.querySelector('[data-titre]').textContent = title;
    ov.querySelectorAll('[data-banniere]').forEach((el, i) => { el.textContent = banners[i][1]; });
    ov.querySelectorAll('[data-libelle]').forEach((el, i) => { el.textContent = fields[i][0]; });
    ov.querySelectorAll('[data-pem]').forEach((el, i) => { el.value = fields[i][1] || ''; });
    return ov;
}

/* Clé privée affichée UNE FOIS — jamais copiée automatiquement. */
function _pkiShowIssuedCert(result) {
    _pkiResultOverlay(`Certificat émis — ${result.common_name || '?'}`, [
        ['success-banner', `Serial : ${result.serial_number || '?'} — expire : ${String(result.expiration || '?')}`],
        ['error-banner', "⚠️ Clé privée affichée une seule fois. Copiez-la et stockez-la maintenant. Elle n'est ni stockée côté serveur, ni récupérable ensuite."],
    ], [['Clé privée', result.private_key], ['Certificat', result.certificate], ['Chaîne CA', result.ca_chain]]);
}

function _pkiShowSignedCsr(result) {
    _pkiResultOverlay(`CSR signée — ${result.dns_name || '?'}`, [
        ['success-banner', `Serial : ${result.serial_number || '?'} — expire : ${result.not_after || '?'}`],
        ['help-text', 'Installez le certificat et la chaîne sur le serveur ; les clients ne gardent que la racine. La clé privée est restée chez vous.'],
    ], [['Certificat', result.certificate], ['Chaîne intermédiaire (sans la racine)', result.ca_chain]]);
}

/* Export pour le test Node ; ignoré dans le navigateur (module y est undefined). */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        _pki, loadPki, expiryBadgeState, PKI_SEUILS_AUTORITE, PKI_SEUILS_CRL, ttlFromSeconds, labModeFromEab, pkiSetupBody,
        pkiReplayReference, pkiReplayChanges, pkiRotateBody, openPkiSetup, openPkiReplay,
        doPkiSetup, openPkiRotate, doPkiRotate, openPkiSignCsr, doPkiSignCsr, pkiRevokeAt,
        pkiCopyUrl, pkiPage, _renderPkiPage, PKI_REPLAY_EXPLANATION,
    };
}
