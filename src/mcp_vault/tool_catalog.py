"""
Catalogue canonique des outils MCP exposés — source unique de vérité (#128).

## Pourquoi ce module existe

Une règle d'accès (`allowed_tools` / `denied_tools`) nomme des outils par motif
`fnmatch`. Jusqu'ici la validation vérifiait seulement qu'il s'agissait de
chaînes : une faute de frappe — `ssx_*` au lieu de `ssh_*` — était **acceptée,
enregistrée, et ne protégeait rien**. Sans message.

⚠️ **Un cas réel a été trouvé en production le 19/08/2026** : la policy
`judilibre-prod-api-key-readonly` porte un motif *denied* `token_create`, qui ne
correspond à **aucun** outre réel — l'outil qui existe, `token_update`, n'était
donc pas couvert. Sans dommage : `token_update` exige la permission `admin`,
contrôlée indépendamment de toute policy. **De la chance, pas de la conception.**

## Pourquoi une validation LEXICALE ne suffit pas

`ssx_*` est un motif irréprochable : alphanumérique, joker bien placé, rien à
signaler. Seule la **correspondance au catalogue réel** l'attrape. C'est la même
conclusion que `mcp-agent` a formulée sur son propre code cette semaine : *une
liste blanche se raisonne par nom exact, jamais par forme.*

## Pourquoi une liste explicite et non une introspection

`auth/policies.py` est importé PAR `server.py` : lire les outils depuis `server`
créerait un cycle d'import. Le décorateur `@mcp.tool()` rend d'ailleurs la
fonction nue — il n'y a pas d'objet-catalogue à interroger.

⚠️ Une liste tenue à la main **dérive**. C'est le risque réel de ce module, et il
est fermé par un test qui compare cette liste à l'ensemble des `@mcp.tool()` de
`server.py` : toute divergence, dans un sens ou dans l'autre, échoue. Sans ce
test, ce fichier serait un piège de plus.
"""

import fnmatch

# Les 39 outils exposés par `@mcp.tool()` dans `server.py`.
# ⚠️ Modifier cette liste sans modifier `server.py` (ou l'inverse) fait échouer
# `tests/test_tool_catalog_128.py::test_le_catalogue_ne_derive_pas_de_server`.
MCP_TOOL_NAMES = frozenset({
    "audit_log",
    "pki_ca_list_roles", "pki_ca_public_key", "pki_ca_role_info",
    "pki_ca_rotate_intermediate", "pki_ca_setup",
    "pki_issue_cert", "pki_list_certs", "pki_revoke_cert",
    "policy_create", "policy_delete", "policy_get", "policy_list",
    "secret_consume", "secret_delete", "secret_generate_password",
    "secret_list", "secret_read", "secret_revoke_wrap", "secret_types",
    "secret_wrap", "secret_wrap_lookup", "secret_wrap_status", "secret_write",
    "ssh_ca_list_roles", "ssh_ca_public_key", "ssh_ca_role_info",
    "ssh_ca_setup", "ssh_operator_access_profiles",
    "ssh_request_operator_access", "ssh_sign_key",
    "system_about", "system_health",
    "token_update",
    "vault_create", "vault_delete", "vault_info", "vault_list", "vault_update",
})


def pattern_designates_a_tool(pattern) -> bool:
    """`pattern` désigne-t-il au moins un outil réel ?

    Même convention d'appel que la décision d'accès
    (`PolicyStore.is_tool_allowed`) : `fnmatch.fnmatch(nom_outil, motif)`. Un
    motif validé ici est donc exactement un motif qui peut matcher à l'exécution.
    """
    if not isinstance(pattern, str) or not pattern:
        return False
    return any(fnmatch.fnmatch(nom, pattern) for nom in MCP_TOOL_NAMES)


def inoperative_patterns(patterns) -> list:
    """Les motifs qui ne désignent AUCUN outil réel, dans l'ordre reçu.

    Tolérant sur l'entrée : un non-itérable rend une liste vide. La validation de
    type des motifs reste le travail de `_validate_and_normalize_policy` — ce
    module ne répond qu'à « ce motif sert-il à quelque chose ».
    """
    if not isinstance(patterns, (list, tuple)):
        return []
    return [p for p in patterns if not pattern_designates_a_tool(p)]
