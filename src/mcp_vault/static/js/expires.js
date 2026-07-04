/* expires.js — Contrat d'expiration des tokens (issue #65).
 *
 * Module ISOLÉ, SANS dépendance navigateur → testable directement sous Node
 * (cf. tests/js/expires_contract.test.js). Chargé AVANT tokens.js dans admin.html :
 * fournit parseExpiresInDays() au scope global du navigateur.
 *
 * Contrat (aligné sur le backend TokenStore.validate_expires_in_days) :
 *   champ vide          → 90  (défaut sûr — JAMAIS illimité par défaut)
 *   "0"                 → 0   = jamais expirer (illimité EXPLICITE)
 *   entier [1, 36500]   → ce nombre de jours
 *   tout le reste       → null (INVALIDE) : float, texte, négatif, hors borne
 *
 * On NE coerce PAS : parseInt("1.5") === 1, parseInt("1abc") === 1, "0" || 90 === 90
 * masqueraient une saisie invalide — c'est précisément la classe de bug de #65.
 * Retour null → l'appelant bloque l'envoi et affiche une erreur.
 */
var EXPIRES_MAX_DAYS = 36500;

function parseExpiresInDays(raw) {
    var s = (raw === null || raw === undefined ? '' : String(raw)).trim();
    if (s === '') return 90;                 // vide → défaut sûr
    if (!/^\d+$/.test(s)) return null;       // entier décimal non signé strict (rejette float/texte/négatif)
    var n = Number(s);
    if (!Number.isSafeInteger(n) || n > EXPIRES_MAX_DAYS) return null;
    return n;                                // 0 = jamais ; sinon N jours
}

/* Export pour le test Node ; ignoré dans le navigateur (module y est undefined). */
if (typeof module !== 'undefined' && module.exports) {
    module.exports = { parseExpiresInDays: parseExpiresInDays, EXPIRES_MAX_DAYS: EXPIRES_MAX_DAYS };
}
