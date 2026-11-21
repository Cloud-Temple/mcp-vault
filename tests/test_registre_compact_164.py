"""#164 — le registre wrap S3 est écrit en JSON compact, et reste lisible
dans les deux sens de déploiement.

Ce que ces tests verrouillent :

1. `_save()` envoie un JSON compact : chaque transition réécrit tout le
   registre en mode S3, l'indentation n'apportait que des octets ;
2. les octets RÉELLEMENT envoyés par `_save()` sont relus par `load()` à
   l'identique, `default=str` compris (une date devient une chaîne) ;
3. un registre écrit par une version antérieure (JSON indenté, forme
   ≤ 0.23.1) reste lu : la montée de version ne demande aucune migration ;
4. le JSON compact est lu par le `load()` de 0.23.1 : `json.loads`, inchangé,
   n'a aucune préférence de présentation. Le test 2 l'exerce, puisque `load()`
   n'a pas été modifié par #164.

Ils ne prétendent RIEN sur la forme du coût : le coût O(N) par écriture et
O(N²) cumulé demeure en mode S3. Les volumes de mission relèvent de
`METADATA_BACKEND=postgres` (une ligne par wrap).
"""

import io
import json
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import MagicMock


def _registre(entrees=()):
    from mcp_vault.vault.wrapping import WrapRegistry

    registre = WrapRegistry(SimpleNamespace(s3_bucket_name="bucket-test"))
    registre._wraps = list(entrees)
    return registre


def _entrees(n=20):
    quand = datetime(2026, 11, 21, 12, 0, tzinfo=timezone.utc)
    return [
        {
            "operation_id": f"op-{i}",
            "mission_id": f"mission-{i % 3}",
            "vault_id": "coffre-test",
            "secret_path": f"chemin/secret-{i}",
            "status": "active",
            "accessor": f"acc-{i:04d}",
            "created_at": quand,  # non sérialisable nativement : default=str
        }
        for i in range(n)
    ]


def _octets_envoyes(registre) -> bytes:
    s3 = MagicMock()
    registre._get_s3_data = MagicMock(return_value=s3)
    assert registre._save() is True
    assert s3.put_object.call_count == 1
    return s3.put_object.call_args.kwargs["Body"]


def _charger(corps: bytes):
    lecteur = _registre()
    s3 = MagicMock()
    s3.get_object.return_value = {"Body": io.BytesIO(corps)}
    lecteur._get_s3_data = MagicMock(return_value=s3)
    lecteur.load()
    return lecteur


def test_save_envoie_un_json_compact_plus_leger_que_l_ancien_format():
    registre = _registre(_entrees())
    corps = _octets_envoyes(registre)

    texte = corps.decode()
    assert "\n" not in texte, "le registre est encore indenté"
    assert '": ' not in texte and '", "' not in texte, "séparateurs non compacts"

    ancien = json.dumps({"wraps": registre._wraps}, indent=2, default=str).encode()
    assert len(corps) < len(ancien), (len(corps), len(ancien))
    # Même contenu logique que l'ancien format : seule la présentation change.
    assert json.loads(corps) == json.loads(ancien)


def test_les_octets_envoyes_sont_relus_a_l_identique():
    registre = _registre(_entrees())
    corps = _octets_envoyes(registre)

    lecteur = _charger(corps)

    assert lecteur._last_load_ok is True
    attendu = [{**e, "created_at": str(e["created_at"])} for e in registre._wraps]
    assert lecteur._wraps == attendu


def test_un_registre_indente_d_une_version_anterieure_reste_lu():
    entrees = [{**e, "created_at": str(e["created_at"])} for e in _entrees()]
    ancien = json.dumps({"wraps": entrees}, indent=2, default=str).encode()

    lecteur = _charger(ancien)

    assert lecteur._last_load_ok is True
    assert lecteur._wraps == entrees
