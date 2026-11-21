#!/usr/bin/env node
'use strict';
/* Contrat de la page PKI de la console (#217), exécuté sous Node.
 *
 * Les VRAIS gestionnaires de static/js/pki.js tournent contre un DOM minimal et
 * une API interceptée. On observe ce que la page ENVOIE (requêtes exactes) et ce
 * qu'elle AFFICHE : si un bouton cessait d'utiliser la logique testée, la requête
 * observée changerait et le contrat échouerait.
 */
const path = require('path');
const assert = require('assert');

/* ── DOM minimal ── */
const elements = new Map();
function element(id) {
    const el = { id, value: '', textContent: '', innerHTML: '', banners: [], classList: { add() {}, remove() {} } };
    el.prepend = (child) => el.banners.push(child);
    elements.set(id, el);
    return el;
}
for (const id of ['page-pki', 'pkiSetupTitle', 'pkiSetupReplayNotice', 'pkiLabMode', 'pkiAcme',
    'pkiDomains', 'pkiLeafTtl', 'pkiRootTtl', 'pkiIntTtl', 'pkiRotateIntTtl', 'pkiSignCsrPem',
    'pkiSignCsrDomain']) element(id);

const overlays = [];
function fakeOverlay() {
    const ov = { className: '', innerHTML: '', created: {} };
    ov.querySelector = (sel) => ov.querySelectorAll(sel)[0];
    ov.querySelectorAll = (sel) => {
        const attr = sel.replace(/^\[|\]$/g, '');
        if (!ov.created[attr]) {
            const count = (ov.innerHTML.match(new RegExp(attr, 'g')) || []).length;
            ov.created[attr] = Array.from({ length: count }, () => ({ value: '', textContent: '' }));
        }
        return ov.created[attr];
    };
    return ov;
}
global.document = {
    getElementById: (id) => elements.get(id) || null,
    createElement: () => fakeOverlay(),
    querySelector: () => ({ disabled: false, textContent: '' }),
    body: { appendChild: (ov) => overlays.push(ov) },
};
global.esc = (value) => String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');   // comme config.js : pas les guillemets
global.fmtDate = () => '';
global.isAdmin = () => true;
const opened = [];
global.openModal = (id) => opened.push(id);
global.closeModal = () => {};
let alerts = [];
global.alert = (m) => alerts.push(m);
let confirmAnswer = true;
let confirms = [];
global.confirm = (m) => { confirms.push(m); return confirmAnswer; };
let clipboard = null;
Object.defineProperty(globalThis, 'navigator', { value: { clipboard: { writeText: (t) => { clipboard = t; } } }, configurable: true });
global.setTimeout = () => 0;

/* ── API interceptée ── */
const FUTUR = new Date(Date.now() + 5 * 86400000).toISOString();
let calls = [];
let server = {};
global.api = async (endpoint, options = {}) => {
    calls.push({ endpoint, method: options.method || 'GET', body: options.body ? JSON.parse(options.body) : undefined });
    const handler = server[endpoint.split('?')[0]] || server[endpoint];
    if (!handler) throw new Error(`endpoint inattendu: ${endpoint}`);
    return typeof handler === 'function' ? handler(endpoint, options) : handler;
};

function scenario({ acme = true, eab = 'new-account-required', total = 2, urls = {}, serial = '12:34', roles } = {}) {
    calls = []; alerts = []; confirms = []; confirmAnswer = true;
    const roleNames = roles || (acme ? ['acme-servers', 'csr-servers'] : ['csr-servers']);
    server = {
        '/pki/status': {
            status: 'ok', initialized: true, root_expires: FUTUR, int_expires: FUTUR,
            root_fingerprint_sha256: 'AA:BB', crl_next_update: FUTUR, cert_count: total,
            acme_enabled: acme, eab_policy: acme ? eab : null, eab_required: acme && eab !== 'not-required',
            csr_domain: 'dbaas.example.test', csr_ttl: '2160h',
            root_pem_url: urls.root || 'https://pki.example.test/pki/ca/root.pem',
            chain_pem_url: 'https://pki.example.test/pki/ca/chain.pem',
            crl_url: 'https://pki.example.test/pki/ca/crl.pem',
            acme_directory: acme ? 'https://pki.example.test/acme/directory' : null,
        },
        '/pki/certs': (endpoint) => {
            const offset = Number(new URLSearchParams(endpoint.split('?')[1]).get('offset'));
            return { status: 'ok', total, offset, limit: 200,
                certs: [{ serial, sans: ['pg-01.dbaas.example.test'], not_after: FUTUR, revoked: false }] };
        },
        '/pki/roles': { status: 'ok', roles: roleNames },
        '/pki/roles/acme-servers': { status: 'ok', role_name: 'acme-servers',
            allowed_domains: ['example.test', '*.example.test'], max_ttl: 2592000, server_flag: true },
        '/pki/roles/csr-servers': { status: 'ok', role_name: 'csr-servers',
            allowed_domains: ['dbaas.example.test'], max_ttl: 7776000, server_flag: true },
        '/pki/setup': { status: 'ok' },
        '/pki/ca/rotate': { status: 'ok', new_issuer_id: 'nouvel-emetteur' },
        '/pki/sign-csr': { status: 'ok', dns_name: 'pg-01.dbaas.example.test', serial_number: '56:78',
            certificate: 'CERT-PEM-CANARI', ca_chain: 'CHAINE-PEM-CANARI', not_after: FUTUR },
        [`/pki/certs/${encodeURIComponent(serial)}/revoke`]: { status: 'ok' },
    };
}
const sent = (endpoint) => calls.filter(c => c.endpoint === endpoint);

const pki = require(path.join(__dirname, '..', '..', 'src', 'mcp_vault', 'static', 'js', 'pki.js'));

(async () => {
    /* 1. Fonctions pures */
    assert.strictEqual(pki.ttlFromSeconds(2592000), '30d');
    assert.strictEqual(pki.ttlFromSeconds(7200), '2h');
    assert.strictEqual(pki.ttlFromSeconds(90), '90s');
    assert.strictEqual(pki.ttlFromSeconds('720h'), '720h');
    assert.strictEqual(pki.ttlFromSeconds(1000001), '');      // aucune unité exacte ≤ 6 chiffres
    assert.strictEqual(pki.ttlFromSeconds(0), '');
    assert.strictEqual(pki.labModeFromEab('not-required'), true);
    assert.strictEqual(pki.labModeFromEab('new-account-required'), false);
    assert.strictEqual(pki.labModeFromEab('always-required'), null);
    assert.ok(pki.pkiSetupBody({ labMode: '', acme: 'true', domains: 'a.test' }).error);
    assert.ok(pki.pkiSetupBody({ labMode: 'false', acme: 'true', domains: ' ' }).error);
    assert.deepStrictEqual(pki.pkiSetupBody({ labMode: 'false', acme: 'false', domains: '', leafTtl: '' }).body,
        { lab_mode: false, acme: false, allowed_domains: [], leaf_ttl: '720h' });
    assert.deepStrictEqual(pki.pkiRotateBody(''), { keep_old_issuer: true, overlap_ttl: '48h' });
    assert.deepStrictEqual(pki.pkiRotateBody(' 8760h '), { keep_old_issuer: true, overlap_ttl: '48h', int_ttl: '8760h' });
    assert.strictEqual(pki.expiryBadgeState(new Date(Date.now() - 1000).toISOString()).label, 'expirée');

    /* 2. Page : tous les rôles, CRL, pagination demandée */
    scenario({ total: 450 });
    await pki.loadPki();
    let html = elements.get('page-pki').innerHTML;
    assert.ok(sent('/pki/certs?limit=200&offset=0').length === 1, 'inventaire paginé demandé');
    assert.ok(sent('/pki/roles/acme-servers').length === 1 && sent('/pki/roles/csr-servers').length === 1);
    assert.ok(html.includes('csr-servers') && html.includes('dbaas.example.test'), 'rôle CSR affiché');
    assert.ok(html.includes('Liste de révocation (CRL)') && html.includes('J-'), 'échéance CRL affichée');
    assert.ok(html.includes('Suivants'), 'page suivante proposée');
    scenario({ total: 450 });
    pki.pkiPage(1);
    await new Promise(r => setImmediate(r));
    await new Promise(r => setImmediate(r));
    assert.ok(sent('/pki/certs?limit=200&offset=200').length === 1, 'page suivante = offset 200');

    scenario({ acme: false });
    await pki.loadPki();
    html = elements.get('page-pki').innerHTML;
    assert.ok(html.includes('csr-servers'), 'rôles affichés même ACME fermé');

    /* 3. Rejeu : pré-remplissage = état lu ; soumission sans modification = corps exact */
    scenario({ acme: true, eab: 'new-account-required' });
    await pki.loadPki();
    pki.openPkiReplay();
    const f = (id) => elements.get(id).value;
    assert.deepStrictEqual([f('pkiLabMode'), f('pkiAcme'), f('pkiDomains'), f('pkiLeafTtl'), f('pkiRootTtl'), f('pkiIntTtl')],
        ['false', 'true', 'example.test, *.example.test', '30d', '', '']);
    assert.ok(elements.get('pkiSetupReplayNotice').textContent.includes('CONSERVÉ'), 'explication affichée');
    await pki.doPkiSetup();
    assert.strictEqual(confirms.length, 1, 'confirmation demandée');
    assert.ok(confirms[0].includes('CONSERVÉ') && confirms[0].includes('Aucun changement'));
    assert.deepStrictEqual(sent('/pki/setup').map(c => c.body),
        [{ lab_mode: false, acme: true, allowed_domains: ['example.test', '*.example.test'], leaf_ttl: '30d' }]);

    /* 4. Rejeu qui ouvre l'enrôlement : changement signalé ; refus → aucun appel */
    scenario({ acme: true, eab: 'new-account-required' });
    await pki.loadPki();
    pki.openPkiReplay();
    elements.get('pkiLabMode').value = 'true';
    confirmAnswer = false;
    await pki.doPkiSetup();
    assert.ok(confirms[0].includes('CHANGEMENT') && confirms[0].includes('LIBRE'), 'changement EAB signalé');
    assert.strictEqual(sent('/pki/setup').length, 0, 'refus de confirmation : aucun setup');

    /* 5. ACME fermé ou EAB inconnu : aucun choix d'enrôlement implicite */
    scenario({ acme: false });
    await pki.loadPki();
    pki.openPkiReplay();
    assert.strictEqual(f('pkiLabMode'), '');
    await pki.doPkiSetup();
    assert.ok(alerts.length === 1 && sent('/pki/setup').length === 0, 'envoi bloqué sans choix explicite');
    scenario({ acme: true, eab: 'always-required' });
    await pki.loadPki();
    pki.openPkiReplay();
    assert.strictEqual(f('pkiLabMode'), '');
    assert.ok(elements.get('pkiSetupReplayNotice').textContent.includes("n'a pas pu être lu"));

    /* 6. Rotation : int_ttl seulement s'il est saisi */
    scenario();
    await pki.loadPki();
    pki.openPkiRotate();
    await pki.doPkiRotate();
    elements.get('pkiRotateIntTtl').value = '8760h';
    await pki.doPkiRotate();
    assert.deepStrictEqual(sent('/pki/ca/rotate').map(c => c.body), [
        { keep_old_issuer: true, overlap_ttl: '48h' },
        { keep_old_issuer: true, overlap_ttl: '48h', int_ttl: '8760h' }]);

    /* 7. Signature de CSR : requête exacte, PEM rendus par .value */
    scenario();
    await pki.loadPki();
    pki.openPkiSignCsr();
    assert.strictEqual(elements.get('pkiSignCsrDomain').textContent, 'dbaas.example.test');
    elements.get('pkiSignCsrPem').value = '  CSR-PEM  ';
    overlays.length = 0;
    await pki.doPkiSignCsr();
    assert.deepStrictEqual(sent('/pki/sign-csr').map(c => c.body), [{ csr: 'CSR-PEM' }]);
    const ov = overlays[0];
    assert.deepStrictEqual(ov.created['data-pem'].map(e => e.value), ['CERT-PEM-CANARI', 'CHAINE-PEM-CANARI']);
    assert.ok(!ov.innerHTML.includes('CANARI'), 'PEM jamais injecté par innerHTML');

    /* 8. Injection : aucune valeur serveur dans un attribut */
    const piege = 'https://x.test/" onmouseover=alert(1)//';
    scenario({ urls: { root: piege }, serial: '</code><img src=x onerror=alert(1)>' });
    await pki.loadPki();
    html = elements.get('page-pki').innerHTML;
    // On examine les BALISES : le piège peut figurer comme texte affiché (c'est
    // voulu, il est échappé), jamais comme balise ou attribut.
    const tags = html.match(/<[a-zA-Z][^>]*>/g) || [];
    assert.ok(tags.length > 20, 'le rendu a bien produit des balises');
    assert.ok(!tags.some(t => /^<img/i.test(t)), 'aucune balise injectée');
    assert.ok(!tags.some(t => /\son(?!click=)\w+=/i.test(t)), 'aucun attribut d\'événement injecté');
    assert.ok(html.includes('&lt;img'), 'le serial piégé est affiché, échappé');
    const handlers = tags.flatMap(t => t.match(/\son\w+="[^"]*"/g) || []);
    const autorises = /^ onclick="(pkiRevokeAt\(\d+\)|pkiCopyUrl\('(root|chain|crl|acme)'\)|pkiPage\(-?1\)|openModal\('modalPkiIssue'\)|openPkiSignCsr\(\)|openPkiRotate\(\)|openPkiReplay\(\))"$/;
    for (const h of handlers) assert.ok(autorises.test(h), `gestionnaire inattendu : ${h}`);
    pki.pkiCopyUrl('root');
    assert.strictEqual(clipboard, piege, 'le bouton copie la valeur exacte');
    await pki.pkiRevokeAt(0);
    assert.strictEqual(sent(`/pki/certs/${encodeURIComponent('</code><img src=x onerror=alert(1)>')}/revoke`).length, 1);

    console.log('pki_console_contract : OK');
})().catch((e) => { console.error(e); process.exit(1); });
