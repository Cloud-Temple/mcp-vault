# -*- coding: utf-8 -*-
"""
Cloisonnement inter-missions du registre de wraps.

Un `operation_id` n'est PAS unique entre missions : c'est le couple
`(operation_id, mission_id)` qui identifie une provision. La consommation
l'utilisait déjà ; quatre autres chemins non.

Le plus grave est DESTRUCTIF et atteignable en mono-instance :
`lookup_and_revoke_by_operation_id` (outil `secret_wrap_lookup`, compensation des
orphelins) sélectionnait par `operation_id` seul puis **révoquait**. Compenser un
orphelin de A détruisait la provision VIVANTE de B.

⚠️ Le filtre d'identité de #115 ne protégeait pas : le broker porte un seul jeton
pour toutes les missions.

Les trois autres : `status_by_operation_id` divulguait l'état des provisions
d'une autre mission ; `mark_active`/`mark_failed` prenaient « la dernière entrée
pending de cet operation_id », donc pouvaient écrire l'accessor de A sur B.

Deux défauts d'honnêteté fermés au passage : `mark_active` rendait le résultat de
`_save()` seul (« succès » sans correspondance), et absence ou ambiguïté
sauvegardaient quand même — une écriture no-op écrase l'état d'une autre
instance (last-write-wins, #51).

Tests mockés (pas de conteneur). Stub hvac : `tests/conftest.py`.
"""
import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

OP = "op-partage"
A = "mission-A"
B = "mission-B"


def run(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


def _registre(entrees=(), *, save_ok=True, echec_a_partir_de=0):
    """
Registre en mémoire qui COMPTE ses sauvegardes.

    Le compteur est le cœur des tests d'absence/ambiguïté : il ne suffit pas
    qu'aucune mutation n'ait lieu, il faut prouver qu'aucune ÉCRITURE n'est
    tentée — sinon on réécrit l'état d'une autre instance par-dessus.

    `echec_a_partir_de` = numéro de sauvegarde (1-indexé) à partir duquel
    `_save()` échoue. Indispensable pour atteindre l'échec de `mark_active` :
    faire échouer TOUTES les sauvegardes fait échouer `register_pending`, et le
    test mesure alors le refus d'enregistrer, pas la restauration de l'état
    (leçon des tests de #78).
    """
    from mcp_vault.vault.wrapping import WrapRegistry

    class EnMemoire(WrapRegistry):
        def __init__(self):
            self._wraps = [dict(e) for e in entrees]
            self._cache_time = float("inf")
            self._last_load_ok = True
            self.sauvegardes = 0

        def load(self):
            pass

        def _maybe_refresh(self):
            pass

        def _save(self) -> bool:
            self.sauvegardes += 1
            if echec_a_partir_de and self.sauvegardes >= echec_a_partir_de:
                return False
            return save_ok

    return EnMemoire()


def _entree(mission, statut="pending", accessor=None, op=OP):
    return {
        "operation_id": op, "accessor": accessor, "mission_id": mission,
        "vault_id": "mcp-mission", "secret_path": "missions/db",
        "created_at": "", "expires_at": "2099-01-01T00:00:00+00:00",
        "status": statut,
    }


def _de(registre, mission):
    """L'UNIQUE entrée de cette mission — échoue bruyamment s'il y en a plusieurs.

    Rendre `next(...)` porterait l'assertion sur une entrée arbitraire dès qu'une
    mission a deux entrées — faux vert ou faux rouge, sans signal.
    """
    entrees = [e for e in registre._wraps if e["mission_id"] == mission]
    assert len(entrees) == 1, (
        f"{len(entrees)} entrée(s) pour {mission!r} : le montage est ambigu, "
        f"l'assertion porterait sur une entrée arbitraire — {registre._wraps!r}")
    return entrees[0]


@pytest.fixture(autouse=True)
def _identite_admin():
    """Les primitives filtrent par identité (#115) — admin explicite pour isoler
    le sujet : ici on teste la frontière de MISSION, pas celle de vault."""
    from tests.conftest import admin_auth_context
    with admin_auth_context():
        yield


# =============================================================================
# 1) LE CHEMIN DESTRUCTIF — la compensation d'une mission n'en touche pas une autre
# =============================================================================

class TestCompensationCloisonnee:

    def _revoquer(self, registre, mission):
        from mcp_vault.vault import wrapping as w
        client = MagicMock()
        client.auth.token.revoke_accessor.return_value = None
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client):
            return run(w.lookup_and_revoke_by_operation_id(OP, mission)), client

    def test_compenser_A_ne_revoque_PAS_la_provision_vivante_de_B(self):
        """Le défaut est DESTRUCTIF : la sélection par `operation_id` seul
        révoquait les deux entrées."""
        registre = _registre([_entree(A, "active", "ACC-A"),
                              _entree(B, "active", "ACC-B")])
        r, client = self._revoquer(registre, A)

        assert r["status"] == "ok", r
        assert r["count_revoked"] == 1, (
            f"{r['count_revoked']} révocation(s) au lieu d'une seule — la "
            f"provision d'une autre mission a été touchée : {r!r}")
        assert _de(registre, A)["status"] == "revoked"
        assert _de(registre, B)["status"] == "active", (
            "la provision VIVANTE de la mission B a été révoquée")

        revoques = [c.kwargs.get("accessor") for c in
                    client.auth.token.revoke_accessor.call_args_list]
        assert revoques == ["ACC-A"], (
            f"accessors révoqués côté OpenBao : {revoques} — celui de B ne doit "
            f"jamais partir")

    def test_l_etat_ambiguous_ne_vient_plus_d_une_autre_mission(self):
        """`ambiguous` est l'état sur lequel `mcp-mission` se replie en
        fail-close, au prix d'orphelins non compensés. Cloisonné, chaque mission
        voit UNE entrée : la compensation redevient possible."""
        registre = _registre([_entree(A, "active", "ACC-A"),
                              _entree(B, "active", "ACC-B")])
        r, _ = self._revoquer(registre, A)

        assert r["state"] == "revoked", (
            f"état {r['state']!r} — une provision d'une autre mission fait "
            f"encore basculer la compensation en ambiguïté")

    def test_une_mission_sans_provision_ne_voit_rien(self):
        registre = _registre([_entree(A, "active", "ACC-A")])
        r, client = self._revoquer(registre, B)

        assert r["state"] == "not_found", r
        assert r["count_revoked"] == 0
        assert _de(registre, A)["status"] == "active"
        client.auth.token.revoke_accessor.assert_not_called()

    def test_deux_entrees_de_LA_MEME_mission_restent_ambigues(self):
        """
        ANTI-COMPLAISANCE : le cloisonnement ne doit pas faire disparaître la
        détection de duplication RÉELLE. Deux entrées du MÊME couple restent une
        anomalie signalée.
        """
        registre = _registre([_entree(A, "active", "ACC-1"),
                              _entree(A, "active", "ACC-2")])
        r, _ = self._revoquer(registre, A)

        assert r["state"] == "ambiguous", r
        assert r["count_revoked"] == 2, r


# =============================================================================
# 2) LA LECTURE D'ÉTAT — pas de divulgation entre missions
# =============================================================================

class TestLectureCloisonnee:

    def _statut(self, registre, mission):
        from mcp_vault.vault import wrapping as w
        with patch.object(w, "get_wrap_registry", return_value=registre):
            return run(w.status_by_operation_id(OP, mission))

    def test_A_ne_voit_pas_l_etat_de_la_provision_de_B(self):
        """
        la lecture révélait l'existence, l'état et la
        durée de vie restante de la provision d'une autre mission.
        """
        registre = _registre([_entree(B, "active", "ACC-B")])
        r = self._statut(registre, A)

        assert r["state"] == "not_found", (
            f"la mission A lit l'état d'une provision de B : {r!r}")
        assert "expires_at" not in r, (
            f"durée de vie d'une provision étrangère divulguée : {r!r}")

    def test_chaque_mission_voit_la_sienne(self):
        """ANTI-COMPLAISANCE : cloisonner ne doit pas aveugler le propriétaire."""
        registre = _registre([_entree(A, "active", "ACC-A"),
                              _entree(B, "consumed", "ACC-B")])

        assert self._statut(registre, A)["state"] == "active"
        assert self._statut(registre, B)["state"] == "consumed"

    def test_la_lecture_ne_mute_rien(self):
        registre = _registre([_entree(A, "active", "ACC-A")])
        self._statut(registre, A)

        assert registre.sauvegardes == 0, "une lecture a écrit sur S3"
        assert _de(registre, A)["status"] == "active"


# =============================================================================
# 3) LES TRANSITIONS DE PROVISIONNEMENT
# =============================================================================

class TestTransitionsCloisonnees:

    def test_mark_active_de_A_n_ecrit_pas_sur_l_entree_de_B(self):
        """
        la sélection prenait « la dernière entrée
        `pending` de cet `operation_id` » — donc celle de B — et lui collait
        l'accessor de A. L'entrée de A restait `pending` pour toujours.
        """
        registre = _registre([_entree(A), _entree(B)])

        assert registre.mark_active(OP, A, "ACC-A") is True
        assert _de(registre, A)["status"] == "active"
        assert _de(registre, A)["accessor"] == "ACC-A"
        assert _de(registre, B)["status"] == "pending", (
            "l'entrée de la mission B a été mutée")
        assert _de(registre, B)["accessor"] is None, (
            "l'accessor de A a été écrit sur la provision de B")

    def test_mark_failed_de_A_n_ecrit_pas_sur_l_entree_de_B(self):
        registre = _registre([_entree(A), _entree(B)])
        registre.mark_failed(OP, A)

        assert _de(registre, A)["status"] == "failed"
        assert _de(registre, B)["status"] == "pending"

    def test_sans_correspondance_mark_active_rend_False_et_n_ecrit_PAS(self):
        """
        Deux défauts d'un coup. la méthode rendait le
        résultat de `_save()` seul, donc `True` — et `wrap_secret` en concluait
        que la provision était corrélée. Elle sauvegardait AUSSI, réécrivant
        l'état mémoire par-dessus une version S3 peut-être plus récente.
        """
        registre = _registre([_entree(B)])

        assert registre.mark_active(OP, A, "ACC-A") is False, (
            "succès annoncé sans aucune entrée mise à jour")
        assert registre.sauvegardes == 0, (
            "sauvegarde no-op : l'état d'une autre instance peut être écrasé")
        assert _de(registre, B)["status"] == "pending"

    def test_ambiguite_traitee_comme_absence_sans_ecriture(self):
        """Deux `pending` du MÊME couple : on ne devine pas laquelle est la bonne."""
        registre = _registre([_entree(A), _entree(A)])

        assert registre.mark_active(OP, A, "ACC-A") is False
        assert registre.sauvegardes == 0
        assert all(e["status"] == "pending" for e in registre._wraps)

    def test_un_echec_de_sauvegarde_ne_laisse_pas_d_active_FANTOME(self):
        """
        si `_save()` échoue après la mutation mémoire,
        l'instance gardait un `active` fantôme qu'une écriture ultérieure aurait
        persisté — alors que l'appelant va révoquer l'accessor en urgence.
        """
        registre = _registre([_entree(A)], save_ok=False)

        assert registre.mark_active(OP, A, "ACC-A") is False
        assert registre.sauvegardes == 1, "la sauvegarde doit avoir été TENTÉE"
        assert _de(registre, A)["status"] == "pending", (
            "état mémoire non restauré : `active` fantôme")
        assert _de(registre, A)["accessor"] is None

    def test_le_cas_nominal_mono_mission_fonctionne_toujours(self):
        """ANTI-COMPLAISANCE : refuser systématiquement passerait tout ci-dessus."""
        registre = _registre([_entree(A)])

        assert registre.mark_active(OP, A, "ACC-A") is True
        assert _de(registre, A)["status"] == "active"
        assert registre.sauvegardes == 1


# =============================================================================
# 4) LE POINT D'ENTRÉE RÉEL — wrap_secret, pas seulement les primitives
# =============================================================================

class TestPointEntreeReel:

    def _wrap(self, registre):
        """Exécute `wrap_secret` avec un OpenBao factice qui réussit."""
        from mcp_vault.vault import wrapping as w
        client = MagicMock()
        client.read.return_value = {"wrap_info": {"token": "s.WT", "accessor": "ACC-NEW"}}
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            return run(w.wrap_secret("mcp-mission", "missions/db", A, OP, 300)), client

    def test_rejouer_une_cle_deja_pending_est_refuse_sans_rien_toucher(self):
        """
        Après un plantage, on ne sait pas si OpenBao a déjà créé un wrap. En
        rattacher un second au même couple rendrait le premier orphelin ET non
        compensable. Refus AVANT toute écriture et avant tout appel OpenBao.
        """
        registre = _registre([_entree(A)])
        r, client = self._wrap(registre)

        assert r["status"] == "error", r
        assert r["error_type"] == "operation_pending", r
        assert registre.sauvegardes == 0, "écriture malgré le refus"
        client.read.assert_not_called()
        assert len(registre._wraps) == 1, "une seconde entrée a été créée"

    def test_un_pending_d_une_AUTRE_mission_ne_bloque_pas(self):
        """
        ANTI-COMPLAISANCE : le refus doit porter sur le COUPLE. Bloquer sur
        l'`operation_id` seul empêcherait deux missions de travailler en
        parallèle — on remplacerait une corruption par un déni de service.
        """
        registre = _registre([_entree(B)])
        r, client = self._wrap(registre)

        assert r["status"] == "ok", r
        client.read.assert_called_once()
        assert _de(registre, A)["status"] == "active"
        assert _de(registre, B)["status"] == "pending"

    def test_un_retry_apres_failed_reste_permis(self):
        registre = _registre([_entree(A, "failed")])
        r, _ = self._wrap(registre)

        assert r["status"] == "ok", r
        assert [e["status"] for e in registre._wraps].count("active") == 1

    def test_mark_active_impossible_fait_revoquer_l_accessor(self):
        """
        Le chemin de repli existait déjà mais n'était JAMAIS emprunté, puisque
        `mark_active` ne pouvait pas rendre False. Ici la sauvegarde échoue :
        le wrap existe côté OpenBao, il ne doit pas être remis à l'appelant.
        """
        # La 1re sauvegarde (register_pending) RÉUSSIT, la 2e (mark_active) échoue.
        registre = _registre([_entree(A, "failed")], echec_a_partir_de=2)
        r, client = self._wrap(registre)

        assert r["status"] == "error", r
        # La révocation d'urgence réussit ici (client factice sans exception) :
        # le code dit donc qu'il n'y a RIEN à compenser. Il ne dit plus
        # `registry_unavailable`, qui promettait « aucune ressource créée » —
        # faux sur ce chemin, où OpenBao a bel et bien créé le wrap.
        assert r["error_type"] == "wrap_created_revoked", r
        assert "wrap_token" not in r, "un jeton non compensable a été remis"
        client.auth.token.revoke_accessor.assert_called_once()


# =============================================================================
# 5) LA SURFACE MCP — les outils transmettent le COUPLE, et valident avant tout
# =============================================================================

class TestSurfaceMCP:
    """
    les bancs existants vérifiaient « la primitive a
    été appelée », pas AVEC QUOI. Un outil qui perdrait ou remplacerait la
    mission rouvrirait la fuite sans faire échouer un seul test.
    """

    def _outils(self):
        from mcp_vault.server import secret_wrap_lookup, secret_wrap_status
        return secret_wrap_lookup, secret_wrap_status

    def test_lookup_transmet_exactement_le_couple(self):
        from tests.conftest import admin_auth_context
        from unittest.mock import AsyncMock
        lookup, _ = self._outils()
        coeur = AsyncMock(return_value={"status": "ok", "state": "not_found"})
        with admin_auth_context(), \
             patch("mcp_vault.vault.wrapping.lookup_and_revoke_by_operation_id", new=coeur):
            run(lookup("op-42", "m-42"))
        coeur.assert_called_once_with("op-42", "m-42")

    def test_status_transmet_exactement_le_couple(self):
        from tests.conftest import admin_auth_context
        from unittest.mock import AsyncMock
        _, statut = self._outils()
        coeur = AsyncMock(return_value={"status": "ok", "state": "not_found"})
        with admin_auth_context(), \
             patch("mcp_vault.vault.wrapping.status_by_operation_id", new=coeur):
            run(statut("op-42", "m-42"))
        coeur.assert_called_once_with("op-42", "m-42")

    @pytest.mark.parametrize("mauvais", ["", "m\nid", "a" * 300, "m#bad", "m id"])
    def test_un_mission_id_invalide_est_refuse_sans_atteindre_le_coeur(self, mauvais):
        """
        Anti-injection de journal (#78/D6) étendu au nouveau paramètre : une
        valeur non validée ne doit atteindre ni la primitive, ni un audit.
        """
        from tests.conftest import admin_auth_context
        from unittest.mock import AsyncMock
        lookup, statut = self._outils()

        for outil, cible in (
            (lookup, "mcp_vault.vault.wrapping.lookup_and_revoke_by_operation_id"),
            (statut, "mcp_vault.vault.wrapping.status_by_operation_id"),
        ):
            coeur = AsyncMock(return_value={"status": "ok", "state": "not_found"})
            with admin_auth_context(), patch(cible, new=coeur):
                r = run(outil("op-valide", mauvais))
            assert r["status"] == "error", (outil.__name__, mauvais, r)
            assert r["error_type"] == "invalid_input", (outil.__name__, r)
            coeur.assert_not_called()
            # La chaîne vide est sous-chaîne de tout : le contrôle de reflet n'a
            # de sens que pour une valeur non vide.
            if mauvais:
                assert mauvais not in r.get("message", ""), (
                    "la valeur non validée est reflétée au client")


# =============================================================================
# 6) LE CYCLE DE VIE DU REFUS — ce qui est fermé, et ce qui reste ouvert
# =============================================================================

class TestCycleDeVieDuRefus:
    """Ces tests FIGENT le comportement livré : le blocage ne dépend pas de
    l'échéance de l'entrée. Libérer la clé sur `expires_at` ne suffirait pas (la
    nouvelle intention créerait une seconde entrée `pending`, donc une ambiguïté),
    et `expires_at` est calculé AVANT l'appel OpenBao — il ne borne pas la durée
    de vie réelle du wrap.
    """

    def _echeance(self, decalage_s):
        from datetime import datetime, timedelta, timezone
        return (datetime.now(timezone.utc) + timedelta(seconds=decalage_s)).isoformat()

    @pytest.mark.parametrize("echeance,cas", [
        (None, "échéance absente"),
        ("", "échéance vide"),
        ("pas-une-date", "échéance illisible"),
        ("2026-08-14T12:00:00", "échéance naïve (sans fuseau)"),
    ])
    def test_aucune_forme_d_echeance_ne_fait_lever_ni_deverrouiller(self, echeance, cas):
        """
        Le blocage ne dépend PAS de l'échéance — aucune de ses formes ne peut donc
        lever ni ouvrir la porte. L'échéance naïve est le cas piégeux : la
        comparaison naïf/aware lève, et seul `ValueError` était intercepté.
        """
        registre = _registre([_entree(A) | {"expires_at": echeance}])
        assert registre.has_pending(OP, A) is True, cas

    def test_une_echeance_depassee_bloque_TOUJOURS(self):
        """
        la reprise se fait avec un
        NOUVEL operation_id, pas par attente. Ce test existe pour qu'une future
        libération par échéance soit un choix explicite, jamais un glissement.
        """
        registre = _registre([_entree(A) | {"expires_at": self._echeance(-3600)}])
        assert registre.has_pending(OP, A) is True

    def test_le_message_prescrit_la_seule_reprise_qui_marche(self):
        from mcp_vault.vault import wrapping as w
        registre = _registre([_entree(A)])
        client = MagicMock()
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r = run(w.wrap_secret("mcp-mission", "missions/db", A, OP, 300))

        assert r["error_type"] == "operation_pending", r
        msg = r["message"].lower()
        assert "nouvel operation_id" in msg, (
            f"le message doit prescrire la reprise réelle : {r['message']!r}")
        assert "300" not in msg, (
            "le message affirme un plafond de TTL qui n'existe pas dans ce code")

    def test_une_indisponibilite_S3_pendant_la_resolution_bloque_AUSSI(self):
        """Le blocage n'exige AUCUN plantage : si OpenBao échoue et que la
        sauvegarde de `mark_failed` échoue aussi, la restauration mémoire
        (voulue) remet l'entrée en `pending`, et la clé est bloquée ensuite.
        """
        from mcp_vault.vault import wrapping as w

        # 1re sauvegarde (register_pending) OK, 2e (mark_failed) KO.
        registre = _registre(echec_a_partir_de=2)
        client = MagicMock()
        client.read.side_effect = RuntimeError("OpenBao injoignable")
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r1 = run(w.wrap_secret("mcp-mission", "missions/db", A, OP, 300))

        assert r1["status"] == "error", r1
        # Sans ce compteur, un chemin qui n'appellerait PAS `mark_failed`
        # laisserait aussi l'entrée en `pending` et le test resterait vert : il
        # prouverait le blocage sans prouver la TENTATIVE de résolution.
        assert registre.sauvegardes == 2, (
            f"{registre.sauvegardes} sauvegarde(s) : l'enregistrement puis la "
            f"tentative de résolution sont attendus")
        assert _de(registre, A)["status"] == "pending", (
            "la restauration mémoire doit laisser `pending` — un `failed` en "
            "mémoire alors que S3 porte `pending` serait un mensonge d'état")

        # La clé est désormais bloquée, SANS qu'aucun plantage n'ait eu lieu.
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r2 = run(w.wrap_secret("mcp-mission", "missions/db", A, OP, 300))

        assert r2["error_type"] == "operation_pending", r2
        assert "nouvel operation_id" in r2["message"].lower()

    def test_un_echec_de_sauvegarde_de_mark_active_bloque_AUSSI_la_cle(self):
        """Même chose par l'autre chemin : OpenBao réussit, la persistance non."""
        from mcp_vault.vault import wrapping as w

        registre = _registre(echec_a_partir_de=2)
        client = MagicMock()
        client.read.return_value = {"wrap_info": {"token": "s.WT", "accessor": "ACC"}}
        cfg = SimpleNamespace(openbao_addr="http://127.0.0.1:8200")
        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r1 = run(w.wrap_secret("mcp-mission", "missions/db", A, OP, 300))

        assert r1["error_type"] == "wrap_created_revoked", r1
        assert registre.sauvegardes == 2, (
            f"{registre.sauvegardes} sauvegarde(s) : sans cette assertion, un "
            f"chemin allant droit à l'erreur sans tenter `mark_active` resterait "
            f"vert")
        client.auth.token.revoke_accessor.assert_called_once()
        assert _de(registre, A)["status"] == "pending"

        with patch.object(w, "get_wrap_registry", return_value=registre), \
             patch.object(w, "_get_client", return_value=client), \
             patch.object(w, "_get_config", return_value=cfg):
            r2 = run(w.wrap_secret("mcp-mission", "missions/db", A, OP, 300))
        assert r2["error_type"] == "operation_pending", r2
