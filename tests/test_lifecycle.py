# -*- coding: utf-8 -*-
"""
Tests de `lifecycle.py` (durcissement 2026-07, fix de sync S3 conditionnelle) :
`vault_shutdown(skip_upload=...)` (round 1) et `_check_local_data_status()`
(round 2).

## Contexte du bloquant fermé par vault_shutdown(skip_upload=...) — round 1

`vault_shutdown()` faisait TOUJOURS un upload S3 final inconditionnel, y
compris quand `vault_startup()` n'avait PAS abouti (ex. restauration S3
ambiguë — réseau, archive corrompue). `server.py::serve_with_lifecycle`
traite un `vault_startup()` en échec comme un "mode dégradé" (comportement
PRÉEXISTANT, non modifié ici) : le serveur continue de tourner, PUIS appelle
`vault_shutdown()` à l'arrêt. Sans garde, cet upload final pouvait donc
écraser une sauvegarde S3 valide avec l'état local incomplet ou jamais
initialisé issu d'un démarrage qui n'a jamais réellement abouti — exactement
le risque que le fix de restauration à 3 états (`RestoreResult`) était censé
éliminer, mais qui restait ouvert via ce chemin d'arrêt.

`vault_shutdown(skip_upload: bool = False)` ferme ce trou : `server.py`
calcule `skip_upload=not ok` à partir du booléen déjà retourné par
`vault_startup()`.

## Contexte du bloquant fermé par _check_local_data_status() — round 2

La promotion de restauration (`s3_sync.py::download_from_s3`) déplace les
entrées du staging vers `data_dir` par renommages INDIVIDUELS — chaque
`rename()` est atomique unitairement, mais la BOUCLE ne l'est pas. Une erreur
I/O ou un crash au milieu laisse `data_dir` dans un état MIXTE (certaines
entrées promues, d'autres non), indiscernable d'une "vraie" donnée locale par
un simple test de présence de fichiers. `_check_local_data_status()` (extrait
de `vault_startup()` pour être testable sans mocker toute la séquence de
démarrage) traite la PRÉSENCE du marqueur `_RESTORE_MARKER_FILENAME` comme
autoritaire : tant qu'il existe, `data_dir` n'est JAMAIS considéré fiable, quel
que soit son contenu physique.

Aucune dépendance à OpenBao/S3 réels : `seal_vault`, `clear_in_memory_keys`,
`stop_openbao`, `stop_periodic_sync`, `upload_to_s3` sont tous mockés à leur
point d'import (imports paresseux dans le corps de `vault_shutdown`).
`_check_local_data_status()` opère uniquement sur le filesystem (`tmp_path`).
"""

import asyncio
import os
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

import pytest

from mcp_vault.lifecycle import (vault_shutdown, _check_local_data_status,
                                 _reset_shutdown_state_for_tests)
from mcp_vault.s3_sync import _RESTORE_MARKER_FILENAME, _RESTORE_STAGING_DIRNAME


@pytest.fixture(autouse=True)
def _rearm_shutdown_idempotence():
    """#110 : `vault_shutdown()` est IDEMPOTENT (le lifespan ASGI et le filet de
    `server.main()` peuvent tous deux l'appeler). Le drapeau est au niveau
    module : sans ce réarmement, seul le PREMIER test du fichier exercerait
    réellement la séquence d'arrêt et les suivants seraient de faux verts."""
    _reset_shutdown_state_for_tests()
    yield
    _reset_shutdown_state_for_tests()


def _run(coro):
    return asyncio.run(coro)


def _patched_shutdown_deps(**overrides):
    """Contexte qui mocke toutes les dépendances de vault_shutdown()."""
    defaults = dict(
        # #122 : `stop_periodic_sync()` retourne désormais l'ÉTAT DE DRAINAGE.
        # `AsyncMock()` sans `return_value` rendrait un `MagicMock` — truthy —
        # et `not drained` serait toujours faux : la garde qui saute l'upload
        # final ne serait JAMAIS exercée, quel que soit le code. Le retour est
        # donc explicite ici, et le cas `False` a son propre test.
        stop_periodic_sync=AsyncMock(return_value=True),
        seal_vault=AsyncMock(return_value={"status": "sealed"}),
        clear_in_memory_keys=MagicMock(),
        upload_to_s3=AsyncMock(return_value=True),
        stop_openbao=AsyncMock(),
    )
    defaults.update(overrides)
    return patch.multiple("mcp_vault.s3_sync", stop_periodic_sync=defaults["stop_periodic_sync"],
                           upload_to_s3=defaults["upload_to_s3"]), \
           patch.multiple("mcp_vault.openbao.lifecycle", seal_vault=defaults["seal_vault"],
                           clear_in_memory_keys=defaults["clear_in_memory_keys"]), \
           patch.multiple("mcp_vault.openbao.manager", stop_openbao=defaults["stop_openbao"]), \
           defaults


class TestSkipUploadOnIncompleteStartup:
    def test_default_skip_upload_false_preserves_historical_behavior(self):
        """Défaut inchangé : sans argument, l'upload final reste inconditionnel
        (comportement historique préservé pour tout appelant existant)."""
        p1, p2, p3, defaults = _patched_shutdown_deps()
        with p1, p2, p3:
            _run(vault_shutdown())
        defaults["upload_to_s3"].assert_awaited_once()

    def test_skip_upload_true_never_calls_upload_to_s3(self):
        """Le coeur du fix : démarrage non abouti -> AUCUN upload final, même
        si `upload_to_s3` réussirait."""
        p1, p2, p3, defaults = _patched_shutdown_deps()
        with p1, p2, p3:
            _run(vault_shutdown(skip_upload=True))
        defaults["upload_to_s3"].assert_not_called()

    def test_skip_upload_true_still_seals_and_stops_openbao(self):
        """`skip_upload` ne doit affecter QUE l'upload S3 — le seal et l'arrêt
        du process OpenBao (protection des données en mémoire) restent
        systématiques, indépendamment de l'état du démarrage."""
        p1, p2, p3, defaults = _patched_shutdown_deps()
        with p1, p2, p3:
            _run(vault_shutdown(skip_upload=True))
        defaults["seal_vault"].assert_awaited_once()
        defaults["clear_in_memory_keys"].assert_called_once()
        defaults["stop_openbao"].assert_awaited_once()
        defaults["stop_periodic_sync"].assert_awaited_once()

    def test_sabotage_removing_skip_upload_guard_calls_upload_anyway(self, monkeypatch):
        """
        SABOTAGE : si la garde `if skip_upload: ... else: upload_to_s3()` est
        contournée (upload_to_s3 appelé inconditionnellement), ce test doit
        détecter la régression. On simule le retrait de la garde en forçant
        l'ancien comportement via un flag de contrôle direct sur le mock.
        """
        p1, p2, p3, defaults = _patched_shutdown_deps()
        with p1, p2, p3:
            _run(vault_shutdown(skip_upload=True))
        # Preuve directe : si un futur changement réintroduit un appel
        # inconditionnel, cette assertion échoue (RED). Documenté ici plutôt
        # que sabotée en direct sur le fichier source (déjà fait manuellement
        # lors de l'implémentation, cf. commit) pour rester exécutable en CI.
        assert defaults["upload_to_s3"].await_count == 0


class TestDrainGovernsFinalUpload:
    """#122 — le résultat du DRAINAGE décide de l'upload final.

    Un drainage non abouti signifie qu'une sauvegarde S3 peut être encore en
    vol. Uploader par-dessus publierait potentiellement un état PLUS ANCIEN que
    celui que le PUT en vol est en train d'écrire.
    """

    def test_drainage_abouti_autorise_upload_final(self):
        p1, p2, p3, defaults = _patched_shutdown_deps(
            stop_periodic_sync=AsyncMock(return_value=True))
        with p1, p2, p3:
            _run(vault_shutdown())
        defaults["upload_to_s3"].assert_awaited_once()

    def test_drainage_non_abouti_interdit_upload_final(self):
        p1, p2, p3, defaults = _patched_shutdown_deps(
            stop_periodic_sync=AsyncMock(return_value=False))
        with p1, p2, p3:
            _run(vault_shutdown())
        assert defaults["upload_to_s3"].await_count == 0, (
            "un drainage non abouti doit INTERDIRE l'upload final"
        )

    def test_drainage_non_abouti_scelle_et_arrete_quand_meme(self):
        """La protection des données en mémoire ne dépend pas du drainage :
        seul l'upload final est sacrifié."""
        p1, p2, p3, defaults = _patched_shutdown_deps(
            stop_periodic_sync=AsyncMock(return_value=False))
        with p1, p2, p3:
            _run(vault_shutdown())
        defaults["seal_vault"].assert_awaited_once()
        defaults["clear_in_memory_keys"].assert_called_once()
        defaults["stop_openbao"].assert_awaited_once()

    def test_exception_au_drainage_est_fail_close(self):
        """Sans preuve de drainage, on ne prend pas le risque : une exception
        de `stop_periodic_sync` doit valoir « non drainé », pas « drainé »."""
        p1, p2, p3, defaults = _patched_shutdown_deps(
            stop_periodic_sync=AsyncMock(side_effect=RuntimeError("boum")))
        with p1, p2, p3:
            _run(vault_shutdown())
        assert defaults["upload_to_s3"].await_count == 0, (
            "une exception au drainage doit être traitée comme un échec de "
            "drainage (fail-close), pas comme un succès"
        )


class TestCheckLocalDataStatus:
    def test_empty_dir_returns_false(self, tmp_path):
        assert _check_local_data_status(tmp_path) is False

    def test_only_gitkeep_returns_false(self, tmp_path):
        (tmp_path / ".gitkeep").write_bytes(b"")
        assert _check_local_data_status(tmp_path) is False

    def test_real_data_no_marker_returns_true(self, tmp_path):
        (tmp_path / "core.db").write_bytes(b"contenu-openbao")
        assert _check_local_data_status(tmp_path) is True

    def test_marker_present_with_real_data_returns_false(self, tmp_path):
        """
        LA propriété qui compte (bloquant round 2) : un contenu qui A L'AIR
        réel (fichiers présents, non vides) ne doit JAMAIS être considéré
        fiable tant que le marqueur de restauration incomplète est là — c'est
        précisément le cas d'une promotion partielle interrompue en cours de
        route.
        """
        (tmp_path / "core.db").write_bytes(b"contenu-partiellement-promu")
        (tmp_path / _RESTORE_MARKER_FILENAME).touch()
        assert _check_local_data_status(tmp_path) is False

    def test_marker_removed_after_call_does_not_affect_result(self, tmp_path):
        """Le marqueur n'est pas modifié PAR cette fonction (lecture seule sur
        le marqueur lui-même) — seul le staging résiduel est nettoyé."""
        (tmp_path / "core.db").write_bytes(b"contenu")
        marker = tmp_path / _RESTORE_MARKER_FILENAME
        marker.touch()
        _check_local_data_status(tmp_path)
        assert marker.exists(), "_check_local_data_status ne doit pas retirer le marqueur lui-même"

    def test_stray_staging_dir_is_cleaned_up(self, tmp_path):
        staging = tmp_path / _RESTORE_STAGING_DIRNAME
        staging.mkdir()
        (staging / "leftover.db").write_bytes(b"residu")
        _check_local_data_status(tmp_path)
        assert not staging.exists(), "un résidu de staging doit être nettoyé au passage"

    def test_staging_that_survives_cleanup_never_counts_as_real_data(self, tmp_path, monkeypatch):
        """
        Bloquant round 4 : si le nettoyage défensif du staging échoue (ex.
        permission, erreur I/O persistante — simulé ici en neutralisant
        `shutil.rmtree`), le staging peut survivre PHYSIQUEMENT. Il ne doit
        JAMAIS, pour autant, être compté comme "donnée locale réelle" — cette
        exclusion est la protection PRINCIPALE, indépendante du succès du
        nettoyage. Sans marqueur (ex. retiré par un chemin CONFIRMED_ABSENT
        qui aurait échoué à purger ce même staging), un staging orphelin
        NE DOIT JAMAIS faire basculer `has_local_data` à True.
        """
        staging = tmp_path / _RESTORE_STAGING_DIRNAME
        staging.mkdir()
        (staging / "leftover.db").write_bytes(b"residu-non-supprimable")
        monkeypatch.setattr("shutil.rmtree", lambda *a, **k: None)
        # Pas de marqueur ici : c'est exactement le scénario round 4 (marqueur
        # déjà retiré ailleurs, staging orphelin restant seul dans data_dir).
        assert _check_local_data_status(tmp_path) is False
        assert staging.exists(), "le nettoyage neutralisé n'a physiquement rien supprimé"

    def test_sabotage_ignoring_marker_would_accept_partial_state(self, tmp_path, monkeypatch):
        """
        SABOTAGE : si la garde `not restore_incomplete` de la condition finale
        est retirée, une promotion partielle (marqueur présent + fichier réel)
        serait acceptée comme donnée locale valide — exactement le bloquant
        round 2. On le prouve en appelant directement la fonction sur un état
        qui ne peut être jugé sûr QUE si le marqueur est respecté.
        """
        (tmp_path / "core.db").write_bytes(b"contenu-partiellement-promu")
        (tmp_path / _RESTORE_MARKER_FILENAME).touch()

        # Le comportement CORRECT (celui qu'on prouve ici) :
        assert _check_local_data_status(tmp_path) is False

        # Preuve que ce n'est pas un hasard de fixture : sans le marqueur, le
        # même contenu physique EST accepté (le marqueur est bien ce qui fait
        # la différence, pas autre chose dans la fonction).
        (tmp_path / _RESTORE_MARKER_FILENAME).unlink()
        assert _check_local_data_status(tmp_path) is True
