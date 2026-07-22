# -*- coding: utf-8 -*-
"""
Validation canonique d'un vault_id — module feuille SANS dépendance.

Volontairement isolé de tout autre module métier (aucun import hvac/OpenBao/
config) pour pouvoir être importé partout sans risque de cycle d'import ni de
dépendance transitive lourde. C'était la justification documentée de CHAQUE
duplication historique de ce pattern (auth/context.py, vault/spaces.py,
auth/mission_bindings.py) avant consolidation ici (revue adversariale round
3 sur PR #97/issue #96, puis fix critique d'isolation owner-based,
2026-07-22/23 — cf. CHANGELOG).

Import ce module, jamais l'inverse : il ne doit dépendre de rien dans
mcp_vault pour rester importable depuis n'importe quel autre module sans
risque de cycle.
"""

import re

# fullmatch (jamais match) : `match` + `$` accepte aussi une position juste
# avant un `\n` final — piège déjà documenté ailleurs dans ce projet
# (is_safe_id, ssh_operator.py). Les 3 anciennes copies de ce pattern
# utilisaient `.match()` ; une seule avait déjà été durcie en fullmatch avant
# la consolidation.
VAULT_ID_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}$')


def is_valid_vault_id(value) -> bool:
    """True si value est un vault_id canonique.

    Alphanumérique + tirets/underscores, 1-64 caractères, commence par un
    caractère alphanumérique. Rejette explicitement toute valeur non-str
    (y compris None).
    """
    return isinstance(value, str) and bool(VAULT_ID_PATTERN.fullmatch(value))
