#!/usr/bin/env node
/* Test de contrat du masquage des secrets dans la console Admin (issue agentic-platform,
 * 2026-07-20), exécuté sous Node — même pattern que expires_contract.test.js
 * (aucune dépendance npm : le dépôt n'a aucun package.json).
 *
 * Couvre isSensitiveField(), renderSecretFieldsInto() ET toggleSecret() elle-même
 * (via un faux DOM + un faux api() injectés en globals avant le require()) : tester
 * seulement les fonctions pures ne prouverait rien sur la vraie mécanique
 * ouverture/repli/purge/concurrence de toggleSecret().
 *
 * Un faux DOM minimal (aucune librairie type jsdom) supporte strictement le sous-
 * ensemble utilisé par vaults.js : createElement/createTextNode/getElementById,
 * appendChild/replaceChildren, classList (add/remove/contains), textContent
 * (sémantique réelle : le setter vide les enfants), dataset, style, addEventListener/
 * click, et innerHTML — avec un espion qui enregistre CHAQUE chaîne jamais écrite,
 * pour prouver qu'aucune valeur sensible n'y transite jamais (piège à régression :
 * si quelqu'un revient à `innerHTML = ...secret...`, le test vire RED immédiatement).
 *
 * Sortie : exit 0 si tous les cas passent, exit 1 sinon (consommé par le wrapper
 * pytest tests/test_frontend_secret_masking.py). */
'use strict';

const path = require('path');
const fs = require('fs');
const vm = require('vm');

/* ═══════════════════════════════════════════════════════════════════════
   Faux DOM minimal
   ═══════════════════════════════════════════════════════════════════════ */

let INNER_HTML_WRITES = [];   // espion : chaque écriture innerHTML, toutes instances confondues
let CLIPBOARD_WRITES = [];    // espion : chaque appel navigator.clipboard.writeText

class FakeClassList {
    constructor() { this._set = new Set(); }
    add(...cls) { for (const c of cls) this._set.add(c); }
    remove(...cls) { for (const c of cls) this._set.delete(c); }
    contains(c) { return this._set.has(c); }
}

class FakeNode {
    constructor(tagName) {
        this.tagName = tagName;
        this.id = '';
        this.className = '';
        this.classList = new FakeClassList();
        this.dataset = {};
        this.style = {};
        this.title = '';
        this.type = '';
        this._attrs = {};
        this._children = [];
        this._isText = false;
        this._text = '';
        this._listeners = {};
        this._innerHTMLRaw = '';
    }
    appendChild(node) { this._children.push(node); return node; }
    replaceChildren(...nodes) { this._children = nodes; }
    setAttribute(name, value) { this._attrs[name] = String(value); }
    getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this._attrs, name) ? this._attrs[name] : null;
    }
    addEventListener(type, fn) { (this._listeners[type] = this._listeners[type] || []).push(fn); }
    click() { (this._listeners.click || []).forEach((fn) => fn()); }
    get textContent() {
        if (this._isText) return this._text;
        return this._children.map((c) => c.textContent).join('');
    }
    set textContent(v) {
        this._isText = false;
        this._children = [];
        const s = v === null || v === undefined ? '' : String(v);
        if (s !== '') {
            const t = new FakeNode('#text');
            t._isText = true;
            t._text = s;
            this._children = [t];
        }
    }
    get innerHTML() { return this._innerHTMLRaw; }
    set innerHTML(v) {
        const s = v === null || v === undefined ? '' : String(v);
        this._innerHTMLRaw = s;
        INNER_HTML_WRITES.push(s);
        this._children = [];
        this._isText = false;
    }
    // Concatène le texte de tout le sous-arbre (utilisé pour prouver une purge complète).
    subtreeText() {
        return this.textContent + this._children.map((c) => (c.subtreeText ? c.subtreeText() : '')).join('');
    }
}

class FakeDocument {
    constructor() { this._byId = new Map(); }
    createElement(tag) { return new FakeNode(tag); }
    createTextNode(text) {
        const t = new FakeNode('#text');
        t._isText = true;
        t._text = text === null || text === undefined ? '' : String(text);
        return t;
    }
    getElementById(id) { return this._byId.has(id) ? this._byId.get(id) : null; }
    registerElement(id, el) { el.id = id; this._byId.set(id, el); }
}

// Recherche récursive dans le sous-arbre (toggleSecret() enveloppe les lignes
// dans un conteneur "secret-detail" — les lignes ne sont donc pas des enfants
// directs de `el`, mais des petits-enfants).
function findFirst(root, predicate) {
    if (!root || !root._children) return null;
    for (const child of root._children) {
        if (predicate(child)) return child;
        const found = findFirst(child, predicate);
        if (found) return found;
    }
    return null;
}

function deferred() {
    let resolve;
    const promise = new Promise((res) => { resolve = res; });
    return { promise, resolve };
}

function realEsc(s) {
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/* ═══════════════════════════════════════════════════════════════════════
   Globals injectés AVANT le require() du vrai vaults.js — même mécanisme que
   le navigateur (api/esc/fmtDate/document sont des identifiants libres résolus
   dynamiquement, pas des imports) : les redéfinir en global.* suffit.
   ═══════════════════════════════════════════════════════════════════════ */

let fakeDoc = new FakeDocument();
global.document = fakeDoc;
global.esc = realEsc;
global.fmtDate = () => 'DATE_TEST';
// Node ≥21 expose déjà un `navigator` global en lecture seule (getter) : on doit
// redéfinir la propriété (assignation directe lève TypeError) pour injecter notre faux.
Object.defineProperty(global, 'navigator', {
    value: { clipboard: { writeText: (v) => { CLIPBOARD_WRITES.push(v); return Promise.resolve(); } } },
    writable: true,
    configurable: true,
});
global.api = async () => ({ status: 'ok', data: {}, version: 1, created_time: '2026-01-01' });

const VAULTS_JS_PATH = path.join(__dirname, '..', '..', 'src', 'mcp_vault', 'static', 'js', 'vaults.js');
const { isSensitiveField, renderSecretFieldsInto, toggleSecret, MASKED_PLACEHOLDER } = require(VAULTS_JS_PATH);

/* ═══════════════════════════════════════════════════════════════════════
   Petit harnais de test (aucune dépendance, même esprit que expires_contract.test.js)
   ═══════════════════════════════════════════════════════════════════════ */

let failed = 0;
let passed = 0;

function assert(condition, message) {
    if (!condition) throw new Error(message || 'assertion échouée');
}

async function test(name, fn) {
    INNER_HTML_WRITES = [];
    CLIPBOARD_WRITES = [];
    fakeDoc = new FakeDocument();
    global.document = fakeDoc;
    global.api = async () => ({ status: 'ok', data: {}, version: 1, created_time: '2026-01-01' });
    try {
        await fn();
        passed++;
    } catch (e) {
        failed++;
        console.error(`FAIL ${name} — ${(e && e.message) || e}`);
    }
}

/* ═══════════════════════════════════════════════════════════════════════
   1. isSensitiveField — table de cas
   ═══════════════════════════════════════════════════════════════════════ */

const SENSITIVE_CASES = [
    // [nom, type, attendu]
    ['password', undefined, true],
    ['PASSWORD', undefined, true],
    ['secret', undefined, true],
    ['private_key', undefined, true],
    ['passphrase', undefined, true],
    ['token', undefined, true],
    ['access_token', undefined, true],
    ['api_key', undefined, true],
    ['totp_secret', undefined, true],
    ['cvv', undefined, true],
    ['seed_phrase', undefined, true],
    ['connection_string', undefined, true],
    ['key', 'api_key', true],           // faux négatif signalé par la revue Codex
    ['key', undefined, true],           // exact, indépendant du type
    ['db_password', undefined, true],   // suffixe préfixé
    ['smtp_connection_string', undefined, true],
    ['wallet_seed_phrase', undefined, true],
    ['card_cvv', undefined, true],
    // Jamais masqué inutilement (exigence explicite du rapport de bug)
    ['public_key', undefined, false],
    ['endpoint', undefined, false],
    ['url', undefined, false],
    ['certificate', undefined, false],
    ['chain', undefined, false],
    ['username', undefined, false],
    ['host', undefined, false],
    // Champs génériques dépendant du _type (recommandation Codex)
    ['content', 'secure_note', true],
    ['content', 'env_file', true],
    ['content', undefined, false],           // "content" seul, sans type connu : pas masqué
    ['number', 'credit_card', true],
    ['number', 'identity', false],           // ex: un futur champ "number" non lié à une carte
    ['phone', 'identity', false],
    ['address', 'identity', false],
];

for (const [name, type, expected] of SENSITIVE_CASES) {
    const got = isSensitiveField(name, type);
    if (got !== expected) {
        failed++;
        console.error(`FAIL isSensitiveField(${JSON.stringify(name)}, ${JSON.stringify(type)}) = ${got}, attendu ${expected}`);
    } else {
        passed++;
    }
}

/* ═══════════════════════════════════════════════════════════════════════
   2. renderSecretFieldsInto — comportement DOM
   ═══════════════════════════════════════════════════════════════════════ */

async function main() {
    await test('champ sensible masqué par défaut (placeholder fixe, jamais la valeur)', async () => {
        const container = fakeDoc.createElement('div');
        renderSecretFieldsInto(container, { password: 'hunter2-le-vrai-secret' });
        const text = container.subtreeText();
        assert(text.includes(MASKED_PLACEHOLDER), 'le placeholder fixe doit être affiché');
        assert(!text.includes('hunter2-le-vrai-secret'), 'la valeur brute ne doit apparaître nulle part par défaut');
        assert(!INNER_HTML_WRITES.some((w) => w.includes('hunter2-le-vrai-secret')), 'aucune écriture innerHTML ne doit contenir la valeur');
    });

    await test('champ non sensible reste visible en clair', async () => {
        const container = fakeDoc.createElement('div');
        renderSecretFieldsInto(container, { username: 'alice@example.com' });
        assert(container.subtreeText().includes('alice@example.com'), 'un champ non sensible doit rester visible');
    });

    await test('révélation ciblée : un seul champ affecté', async () => {
        const container = fakeDoc.createElement('div');
        renderSecretFieldsInto(container, { password: 'SECRET-A', api_key_or_whatever: 'valeur-publique-ish', notes: 'texte libre' });
        // Les 2 boutons du champ password sont les 2 premiers boutons ajoutés à la 1ère ligne.
        const passwordRow = container._children[0];
        const revealBtn = passwordRow._children.find((c) => c.tagName === 'button' && c.title === 'Afficher');
        assert(revealBtn, 'le bouton Afficher doit exister pour un champ sensible');
        revealBtn.click();
        const textAfterReveal = container.subtreeText();
        assert(textAfterReveal.includes('SECRET-A'), 'le clic sur Afficher doit révéler la valeur RÉELLE et COMPLÈTE');
        assert(textAfterReveal.includes('texte libre'), 'les autres champs restent inchangés');
        assert(revealBtn.title === 'Masquer', 'le libellé du bouton doit basculer sur Masquer');
    });

    await test('masquer retire à nouveau la valeur du DOM', async () => {
        const container = fakeDoc.createElement('div');
        renderSecretFieldsInto(container, { password: 'SECRET-B' });
        const row = container._children[0];
        const revealBtn = row._children.find((c) => c.tagName === 'button' && c.title === 'Afficher');
        revealBtn.click();
        assert(container.subtreeText().includes('SECRET-B'), 'précondition : la valeur doit être visible après le 1er clic');
        revealBtn.click();
        assert(!container.subtreeText().includes('SECRET-B'), 'un second clic doit remasquer la valeur');
        assert(revealBtn.title === 'Afficher', 'le libellé doit revenir à Afficher');
    });

    await test('copier nécessite une action explicite et copie uniquement la valeur ciblée', async () => {
        const container = fakeDoc.createElement('div');
        renderSecretFieldsInto(container, { password: 'SECRET-COPY', secret: 'AUTRE-SECRET' });
        assert(CLIPBOARD_WRITES.length === 0, 'aucune copie automatique au rendu');
        const passwordRow = container._children[0];
        const copyBtn = passwordRow._children.find((c) => c.tagName === 'button' && c.title === 'Copier');
        copyBtn.click();
        assert(CLIPBOARD_WRITES.length === 1, 'un clic doit déclencher exactement une copie');
        assert(CLIPBOARD_WRITES[0] === 'SECRET-COPY', 'la copie doit contenir la valeur ciblée exacte, pas une autre');
    });

    await test('valeur contenant du HTML/JS reste inoffensive et exacte (textContent, jamais innerHTML)', async () => {
        const payload = '<img src=x onerror="steal()"><script>alert(1)</script>';
        const container = fakeDoc.createElement('div');
        renderSecretFieldsInto(container, { password: payload });
        assert(!INNER_HTML_WRITES.some((w) => w.includes(payload)), 'la valeur ne doit jamais transiter par innerHTML');
        const row = container._children[0];
        const revealBtn = row._children.find((c) => c.tagName === 'button' && c.title === 'Afficher');
        revealBtn.click();
        const valueEl = row._children.find((c) => c.className === 'secret-field-value');
        assert(valueEl.textContent === payload, 'textContent doit restituer la chaîne EXACTE, verbatim, jamais interprétée');
    });

    /* ═══════════════════════════════════════════════════════════════════
       3. toggleSecret() — vraie mécanique ouverture/repli/purge/concurrence
       ═══════════════════════════════════════════════════════════════════ */

    await test('toggleSecret() : ouverture normale masque les champs sensibles, jamais en clair dans innerHTML', async () => {
        const el = fakeDoc.createElement('div');
        el.classList.add('hidden');
        fakeDoc.registerElement('sd_1', el);
        global.api = async () => ({ status: 'ok', data: { password: 'OUVERTURE-NORMALE' }, version: 3, created_time: '2026-01-01' });

        await toggleSecret('v1', 'p1', 'sd_1');

        assert(!el.classList.contains('hidden'), 'la fiche doit être ouverte');
        assert(!el.subtreeText().includes('OUVERTURE-NORMALE'), 'valeur masquée par défaut');
        assert(!INNER_HTML_WRITES.some((w) => w.includes('OUVERTURE-NORMALE')), 'jamais via innerHTML');
    });

    await test('toggleSecret() : repli purge complètement le contenu rendu', async () => {
        const el = fakeDoc.createElement('div');
        el.classList.add('hidden');
        fakeDoc.registerElement('sd_2', el);
        global.api = async () => ({ status: 'ok', data: { password: 'A-PURGER' }, version: 1, created_time: '2026-01-01' });

        await toggleSecret('v1', 'p2', 'sd_2');
        // Révéler la valeur avant de replier, pour prouver que MÊME révélée elle disparaît.
        const row = findFirst(el, (c) => c.className === 'secret-field-row');
        const revealBtn = row._children.find((c) => c.tagName === 'button' && c.title === 'Afficher');
        revealBtn.click();
        assert(el.subtreeText().includes('A-PURGER'), 'précondition : valeur révélée avant repli');

        await toggleSecret('v1', 'p2', 'sd_2');  // repli

        assert(el.classList.contains('hidden'), 'la fiche doit être repliée');
        assert(el._children.length === 0, 'replaceChildren() doit vider tout le sous-arbre au repli');
        assert(!el.subtreeText().includes('A-PURGER'), 'aucune trace de la valeur, même précédemment révélée');
    });

    await test('toggleSecret() : réponse tardive après repli ne doit JAMAIS repeupler la fiche (course confirmée par Codex)', async () => {
        const el = fakeDoc.createElement('div');
        el.classList.add('hidden');
        fakeDoc.registerElement('sd_3', el);
        const d = deferred();
        global.api = () => d.promise;

        const openPromise = toggleSecret('v1', 'p3', 'sd_3');  // déclenche la requête, reste en attente
        assert(!el.classList.contains('hidden'), 'la fiche passe visible dès l\'ouverture, avant la résolution réseau');

        await toggleSecret('v1', 'p3', 'sd_3');  // repli AVANT que la requête ne réponde
        assert(el.classList.contains('hidden'), 'la fiche doit être repliée');
        assert(el._children.length === 0, 'aucun contenu ne doit rester après le repli');

        d.resolve({ status: 'ok', data: { password: 'REPONSE-TARDIVE' }, version: 1, created_time: '2026-01-01' });
        await openPromise;  // laisser la continuation de la requête tardive s'exécuter

        assert(el.classList.contains('hidden'), 'la fiche doit RESTER repliée malgré la réponse tardive');
        assert(el._children.length === 0, 'la réponse tardive ne doit rien avoir réinséré');
        assert(!el.subtreeText().includes('REPONSE-TARDIVE'), 'la valeur tardive ne doit apparaître nulle part');
        assert(!INNER_HTML_WRITES.some((w) => w.includes('REPONSE-TARDIVE')), 'jamais via innerHTML non plus');
    });

    await test('toggleSecret() : ouverture A puis repli/réouverture B, résolution tardive de A ne doit jamais écraser B', async () => {
        const el = fakeDoc.createElement('div');
        el.classList.add('hidden');
        fakeDoc.registerElement('sd_4', el);
        const dA = deferred();
        global.api = () => dA.promise;

        const pA = toggleSecret('v1', 'p4', 'sd_4');       // A : ouverture, requête en vol
        await toggleSecret('v1', 'p4', 'sd_4');            // repli de A

        const dB = deferred();
        global.api = () => dB.promise;
        const pB = toggleSecret('v1', 'p4', 'sd_4');       // B : réouverture, nouvelle requête en vol

        // Marqueur NON sensible (donc affiché en clair) pour distinguer sans ambiguïté le
        // rendu de A de celui de B — un champ sensible masqué afficherait le MÊME
        // placeholder fixe dans les deux cas et ne prouverait rien sur "qui" s'est affiché.
        dA.resolve({ status: 'ok', data: { marker: 'VIENT-DE-A', password: 'CONTENU-A-PERIME' }, version: 1, created_time: '2026-01-01' });
        await pA;  // A tardif : doit être ignoré (repli déjà survenu, puis B a démarré)

        assert(!el.subtreeText().includes('VIENT-DE-A'), 'A ne doit jamais s\'afficher après avoir été périmé par le repli puis par B');
        assert(el._children.length === 0 || !el.classList.contains('hidden'), 'l\'état ne doit pas être incohérent après A');

        dB.resolve({ status: 'ok', data: { marker: 'VIENT-DE-B', password: 'CONTENU-B-VALIDE' }, version: 1, created_time: '2026-01-01' });
        await pB;

        assert(!el.classList.contains('hidden'), 'B doit être bien ouvert au final');
        assert(el.subtreeText().includes('VIENT-DE-B'), 'le contenu de B doit être bien rendu (A ne l\'a pas écrasé)');
        assert(!el.subtreeText().includes('VIENT-DE-A'), 'A ne doit jamais coexister avec B dans le DOM final');
        assert(!el.subtreeText().includes('CONTENU-B-VALIDE'), 'le champ sensible de B reste masqué par défaut');
    });

    await test('toggleSecret() : erreur API ne fuite rien et ne casse pas la garde de génération', async () => {
        const el = fakeDoc.createElement('div');
        el.classList.add('hidden');
        fakeDoc.registerElement('sd_5', el);
        global.api = async () => ({ status: 'error', message: 'accès refusé' });

        await toggleSecret('v1', 'p5', 'sd_5');

        assert(!el.classList.contains('hidden'), 'la fiche reste ouverte pour afficher l\'erreur');
        assert(el.innerHTML.includes('accès refusé'), 'le message d\'erreur doit être affiché');
    });

    /* ═══════════════════════════════════════════════════════════════════
       4. Preuve historique RED : l'ANCIEN code (figé, chargé via vm car il
       n'exportait rien) fuitait bien la valeur en clair via innerHTML.
       Ce test est INVERSÉ par construction (il documente le bug corrigé par
       ce chantier) — ne JAMAIS le faire disparaître, ne JAMAIS le faire passer
       au vert en modifiant la fixture : un GREEN ici signifierait que la
       fixture historique a été altérée, pas que le bug n'existait pas.
       ═══════════════════════════════════════════════════════════════════ */

    await test('[preuve historique] l\'ancien toggleSecret() (figé, pré-correctif) FUITAIT la valeur en clair via innerHTML', async () => {
        const legacySource = fs.readFileSync(path.join(__dirname, 'fixtures', 'legacy_toggle_secret_snippet.js'), 'utf8');
        const legacyInnerHtmlWrites = [];
        const legacyDoc = new FakeDocument();
        // Contexte vm minimal reproduisant exactement l'environnement navigateur attendu
        // par l'ancien code (document/api/esc/fmtDate en portée libre, comme dans un <script>).
        const ctx = {
            document: legacyDoc,
            api: async () => ({ status: 'ok', data: { password: 'FUITE-HISTORIQUE-CONFIRMEE' }, version: 1, created_time: '2026-01-01' }),
            esc: realEsc,
            fmtDate: () => 'DATE_TEST',
            console,
        };
        // L'espion doit voir les écritures innerHTML du contexte vm : on intercepte via
        // un FakeNode dont le setter innerHTML pousse dans legacyInnerHtmlWrites au lieu
        // du tableau global (le contexte vm est isolé, mais partage la même classe FakeNode
        // par closure — on redéfinit temporairement le setter pour cette instance seule
        // n'est pas nécessaire : FakeNode pousse déjà dans INNER_HTML_WRITES module-level,
        // qu'on lit directement après exécution).
        INNER_HTML_WRITES = [];
        vm.createContext(ctx);
        vm.runInContext(legacySource, ctx);

        const el = legacyDoc.createElement('div');
        el.classList.add('hidden');
        legacyDoc.registerElement('legacy_1', el);

        await ctx.toggleSecret('v1', 'p1', 'legacy_1');

        assert(
            INNER_HTML_WRITES.some((w) => w.includes('FUITE-HISTORIQUE-CONFIRMEE')),
            'PREUVE HISTORIQUE ATTENDUE : l\'ancien code devait injecter la valeur brute en clair via innerHTML — ' +
            'si cette assertion échoue, la fixture légale a été altérée ou ne reflète plus le bug d\'origine'
        );
    });

    /* ═══════════════════════════════════════════════════════════════════
       5. tokens.js — contrats statiques (scénarios 8/9 du rapport de bug)
       ═══════════════════════════════════════════════════════════════════ */

    function extractFunctionBody(source, functionName) {
        const startMarker = source.indexOf(`function ${functionName}(`);
        if (startMarker === -1) throw new Error(`fonction ${functionName} introuvable`);
        const braceStart = source.indexOf('{', startMarker);
        let depth = 0;
        for (let i = braceStart; i < source.length; i++) {
            if (source[i] === '{') depth++;
            else if (source[i] === '}') {
                depth--;
                if (depth === 0) return source.slice(braceStart, i + 1);
            }
        }
        throw new Error(`accolade fermante introuvable pour ${functionName}`);
    }

    await test('tokens.js : le rendu de la table ne référence jamais raw_token/hash complet, seulement hash_prefix', async () => {
        const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'mcp_vault', 'static', 'js', 'tokens.js'), 'utf8');
        const loadTokensBody = extractFunctionBody(src, 'loadTokens');
        assert(!loadTokensBody.includes('raw_token'), 'loadTokens() ne doit jamais référencer raw_token');
        assert(!/\bt\.hash\b(?!_prefix)/.test(loadTokensBody), 'loadTokens() ne doit jamais référencer t.hash (seulement t.hash_prefix)');
        assert(loadTokensBody.includes('hash_prefix'), 'loadTokens() doit bien afficher hash_prefix');
        assert(loadTokensBody.includes('non utilisable pour se connecter'), 'le tooltip de clarification doit être présent sur la colonne Hash');
    });

    await test('tokens.js : raw_token n\'apparaît QUE dans le bloc de création à affichage unique', async () => {
        const src = fs.readFileSync(path.join(__dirname, '..', '..', 'src', 'mcp_vault', 'static', 'js', 'tokens.js'), 'utf8');
        const createTokenBody = extractFunctionBody(src, 'doCreateToken');
        const occurrencesInFile = (src.match(/raw_token/g) || []).length;
        const occurrencesInCreateBlock = (createTokenBody.match(/raw_token/g) || []).length;
        assert(occurrencesInFile === occurrencesInCreateBlock, 'raw_token ne doit apparaître QUE dans doCreateToken()');
        assert(createTokenBody.includes("data.status === 'created' && data.raw_token"), 'le raw_token doit rester gardé par le contrat de création unique');
        assert(createTokenBody.includes('une seule fois'), 'le message "affiché une seule fois" doit rester présent');
    });

    /* ─── Bilan ─── */
    if (failed) {
        console.error(`${failed} cas en échec, ${passed} cas réussis`);
        process.exit(1);
    }
    console.log(`OK — ${passed} cas de contrat de masquage des secrets vérifiés`);
}

main();
