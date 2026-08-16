# -*- coding: utf-8 -*-
"""
Double de magasin exposant les façades async (issue #123).

Depuis le lot 3 de #110, les handlers admin et les outils MCP n'appellent plus
`store.create(...)` mais `await store.acreate(...)` : les mutations font un PUT
S3 synchrone, et exécutées dans la boucle elles gèlent tout le service.

La vraie façade **n'ajoute aucune logique** — elle exécute la méthode synchrone
hors boucle, sous le verrou du magasin, et rend son résultat. Ce double reproduit
exactement ce contrat.

⚠️ Pourquoi pas un `AsyncMock` sur `acreate` : les bancs configurent et
inspectent la méthode SYNCHRONE (`store.create.return_value`,
`store.create.assert_called_with(...)`). C'est la bonne cible — elle reste la
seule implémentation réelle. Un `AsyncMock` séparé les ferait porter sur un objet
que la production n'exécute pas, et un changement de la méthode synchrone
passerait alors inaperçu.
"""

from unittest.mock import MagicMock

# Verbes de mutation des quatre magasins. `a` + verbe = nom de la façade.
_VERBES = frozenset({"create", "update", "delete", "revoke", "purge", "purge_revoked"})


class DoubleMagasin(MagicMock):
    """`MagicMock` qui relaie `a<verbe>` vers `<verbe>`, comme la vraie façade."""

    def __getattr__(self, name):
        if name.startswith("a") and name[1:] in _VERBES:
            synchrone = getattr(self, name[1:])

            async def _facade(*args, **kwargs):
                return synchrone(*args, **kwargs)

            return _facade
        return super().__getattr__(name)
