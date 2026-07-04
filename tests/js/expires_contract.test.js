#!/usr/bin/env node
/* Test de contrat de parseExpiresInDays (issue #65), exécuté sous Node.
 *
 * Vérifie que le module frontend static/js/expires.js respecte le MÊME contrat strict
 * que le backend, SANS coercition. C'est la classe de bug de #65 : l'ancien code
 * `parseInt(v) || 90` transformait "0" → 90, "1.5" → 1, "1abc" → 1.
 *
 * Sortie : exit 0 si tous les cas passent, exit 1 sinon (consommé par le wrapper pytest
 * tests/test_frontend_expires.py). */
const path = require('path');
const mod = require(path.join(__dirname, '..', '..', 'src', 'mcp_vault',
                              'static', 'js', 'expires.js'));
const parseExpiresInDays = mod.parseExpiresInDays;

const cases = [
    // [entrée, attendu]
    ['', 90],            // vide → défaut sûr (JAMAIS illimité par défaut)
    ['   ', 90],         // blancs → défaut
    [null, 90],          // null → défaut
    [undefined, 90],     // undefined → défaut
    ['0', 0],            // 0 = jamais expirer (illimité EXPLICITE)
    ['  0  ', 0],        // trim conservé
    ['90', 90],
    ['365', 365],
    ['36500', 36500],    // borne haute incluse
    ['1.5', null],       // float rejeté (parseInt eût donné 1)
    ['0.0', null],       // float rejeté (parseInt eût donné 0)
    ['1abc', null],      // garbage rejeté (parseInt eût donné 1)
    ['-1', null],        // négatif rejeté
    ['+5', null],        // signe explicite rejeté (contrat [0-9]+ strict)
    ['٥', null],    // ٥ = chiffre arabe (non-ASCII) rejeté
    ['36501', null],     // hors borne
    ['abc', null],       // texte rejeté
    ['1e3', null],       // notation exponentielle rejetée
];

let failed = 0;
for (const pair of cases) {
    const input = pair[0], expected = pair[1];
    const got = parseExpiresInDays(input);
    if (got !== expected) {
        console.error('FAIL parseExpiresInDays(' + JSON.stringify(input) + ') = '
                      + JSON.stringify(got) + ', attendu ' + JSON.stringify(expected));
        failed++;
    }
}
if (mod.EXPIRES_MAX_DAYS !== 36500) {
    console.error('FAIL EXPIRES_MAX_DAYS = ' + mod.EXPIRES_MAX_DAYS + ' (attendu 36500)');
    failed++;
}

if (failed) { console.error(failed + ' cas en échec'); process.exit(1); }
console.log('OK — ' + cases.length + ' cas de contrat parseExpiresInDays vérifiés');
