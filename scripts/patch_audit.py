#!/usr/bin/env python3
"""Script historique, obsolète depuis l'intégration native de l'audit.

Conservé pour expliquer l'ancien jalon de migration. Il ne doit plus modifier
``server.py`` : ses remplacements textuels ne correspondent plus au serveur
MCP v2 et l'audit fait désormais partie du code applicatif.
"""

raise SystemExit(
    "scripts/patch_audit.py est obsolète : l'audit est déjà intégré au serveur."
)
