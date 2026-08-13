#!/usr/bin/env node
/* Contrat frontend de la porte de login face à un coffre DÉGRADÉ (issue #103).
 *
 * Le défaut évité : `/admin/api/health` renvoie désormais `degraded` quand la
 * disponibilité ne l'est pas. La garde d'origine était `health.status !== 'ok'`
 * → un exploitant se serait retrouvé ENFERMÉ DEHORS pendant l'incident, au
 * moment précis où la console sert à diagnostiquer et à desceller.
 *
 * Ce test vérifie la SÉMANTIQUE, pas seulement qu'un mot est accepté : les
 * valeurs de refus (jeton invalide, corps inattendu, absence de champ) doivent
 * rester refusées, sinon la garde n'en serait plus une.
 *
 * Sortie : exit 0 si tous les cas passent, exit 1 sinon (consommé par le
 * wrapper pytest tests/test_frontend_health_login_103.py). */
const path = require('path');
const mod = require(path.join(__dirname, '..', '..', 'src', 'mcp_vault',
                              'static', 'js', 'api.js'));
const healthAllowsLogin = mod.healthAllowsLogin;

const cases = [
    // [statut renvoyé par /admin/api/health, login autorisé ?]
    ['ok', true],            // coffre sain
    ['degraded', true],      // coffre dégradé — DOIT rester administrable
    ['error', false],        // refus explicite de l'API
    ['unauthorized', false],
    ['', false],             // corps vide / champ absent
    [undefined, false],
    [null, false],
    ['OK', false],           // casse stricte — pas de coercition
    ['Degraded', false],
    ['ok ', false],          // pas de trim implicite
    [0, false],              // pas de coercition de type
    [1, false],
    [true, false],
    [{ status: 'ok' }, false],
];

let echecs = 0;
for (const [entree, attendu] of cases) {
    const obtenu = healthAllowsLogin(entree);
    if (obtenu !== attendu) {
        echecs++;
        console.error(`ÉCHEC : healthAllowsLogin(${JSON.stringify(entree)}) = ` +
                      `${obtenu}, attendu ${attendu}`);
    }
}

if (echecs > 0) {
    console.error(`${echecs} cas en échec sur ${cases.length}`);
    process.exit(1);
}
console.log(`OK — ${cases.length} cas de contrat vérifiés`);
