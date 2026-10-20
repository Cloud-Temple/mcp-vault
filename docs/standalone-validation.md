# Matrice #187 : preuves et qualification restante

C-L, C-E, P-L et P-E désignent Compose/Python avec PG local unique/externe dédié
ou partagé. Chaque ligne native doit être exécutée sur les quatre variantes
avec A neuf et B témoin. Les comptes logiciels réels figurent au rapport local.

| AC | Couture logicielle | Qualification native restante |
| --- | --- | --- |
| 1, domaine neuf | Config fermée, chemins/identités, collision avant effets | A neuf et B inchangé avant/après |
| 2, quatre parcours | Base externe, override unique volume, même production | Résolution Compose officielle, lancement et endpoint par variante |
| 3, TLS/fichiers | SAN généré, 0700/0600, nofollow/exclusif, CA RO | UID réels, TLS positif et mauvais SAN/CA refusés |
| 4, auth avant SQL | lookup-self avant KV ; mêmes Settings/root seul, aucun fallback | Bao/unseal/auth positive et négative avant toute SQL |
| 5, rôles/ACL | Six identités prévalidées, membership explicite, modèle SQL strict | Catalogues PG16+, app/maintenance sans SET ROLE, DBACL/default ACL non PUBLIC |
| 6, réserve | M unique, garde produit inchangée | REST/MCP/CLI admin Copy refusent anciens/nouveaux chemins M, wrap/batch/SSH compris |
| 7, installation | DDL/seed neufs explicites, Copy limité, carriers sans retry | v2 sans Mission, v3/v4 préservés, receipts et readiness négative |
| 8, API/audit | Suites existantes #178/#179 et garde technique | Batch/grant/revoke/audit/export/maintenance, positif A et refus B |
| 9, panne/UNKNOWN | ACK perdu sans redispatch, auth refusée avant SQL | Pannes PG/TLS/Bao, budgets mesurés, pas de faux 401/403 |
| 10, restart/restore | Freeze → dump stable → seal ; hash/OID/ACL relus | Restart réel, restore neuf schéma/seed/audit/ACL/révocations ; B intact |
| 11, retour | Zéro prouvé, action reopen-source-zero, dirty interdit Source ancien | Domaine R0 zéro puis R1 muté : dump Copy frais → Return, mutation/revoke/audit conservés |
| 12, versions | Mesure serveur avant DDL, recette/client distincts | Serveur, libpq, outils dump/restore, produit/verrou et digests datés |
| 13, docs/CI | FR/EN, exemple synthétique, packaging et suite pure | Builds production/test/operator, santé canonique et WAF réels |
| 14, revues | Plan approuvé, diff livré pour revue fraîche | Revue indépendante finale avec lecture mémoire réelle et limites |

Conserver `tests/postgres/test_public_interfaces.py` et ses objets exclusifs ;
utiliser son admission explicite puis un nouveau processus pour le groupe final
après restart/restore. Réutiliser les suites #178/#179. Les règles de rétention,
auth et secrets ne changent pas ; #102/#105 ne sont pas absorbés.

CI future : builds production/test/operator, imports publics, suite complète et
étape santé canonique `.github/workflows/ci.yml`, puis preuve TLS/PG/Bao réelle.
Le mandat local logiciel n'exécute aucune phase Docker/services. Ne pas compter
leurs skips comme succès. Préserver les archives et volumes privés ; la
restauration du journal JSONL reste INCONNUE avant mesure dédiée.

Référence de départ immuable :
[`config.py`, Settings PG et chemins](https://github.com/Cloud-Temple/mcp-vault/blob/dcbcefb605dfd0a4576806b30ee59346d9e8ba52/src/mcp_vault/config.py#L39-L99),
[`operator.py`, CAS des connexions](https://github.com/Cloud-Temple/mcp-vault/blob/dcbcefb605dfd0a4576806b30ee59346d9e8ba52/src/mcp_vault/storage/operator.py#L73-L105),
[`operator.py`, modes et actions brutes](https://github.com/Cloud-Temple/mcp-vault/blob/dcbcefb605dfd0a4576806b30ee59346d9e8ba52/src/mcp_vault/storage/operator.py#L227-L246),
[`reserved_metadata.py`, réservation d'un seul mount](https://github.com/Cloud-Temple/mcp-vault/blob/dcbcefb605dfd0a4576806b30ee59346d9e8ba52/src/mcp_vault/reserved_metadata.py#L14-L25),
[`audit_schema.py`, prérequis maintenance](https://github.com/Cloud-Temple/mcp-vault/blob/dcbcefb605dfd0a4576806b30ee59346d9e8ba52/src/mcp_vault/storage/audit_schema.py#L14-L45).
Ces références décrivent le code de départ, pas une exécution native ni une
version serveur qualifiée. Le code applicatif `src/` n'est pas modifié ici.
