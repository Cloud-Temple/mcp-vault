#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rotation SÛRE d'ADMIN_BOOTSTRAP_KEY (issue #121).

## Pourquoi ce script existe

`ADMIN_BOOTSTRAP_KEY` chiffre l'objet S3 qui contient les clés d'unseal
d'OpenBao. Changer sa valeur sans re-chiffrer cet objet empêche tout
**redémarrage à froid** : les clés d'unseal ne sont plus déchiffrables, donc le
coffre ne peut plus s'ouvrir. Sans l'ancienne valeur ET une copie intacte de
l'objet chiffré, les secrets sont perdus.

## ⚠️ EXÉCUTION EXCLUSIVE OBLIGATOIRE

**Arrêter toutes les instances mcp-vault avant de lancer ce script.** Une
instance vivante (ou une autre rotation, une initialisation, une migration
legacy) peut réécrire l'objet chiffré pendant l'opération : le script écrirait
alors par-dessus une version plus récente, dont le volume peut dépendre.
Le script se protège en relisant et comparant l'objet (contenu + ETag) juste
avant l'écriture, et **abandonne au moindre changement** — mais cette garde ne
remplace pas l'exclusion.

## Séquence

  1. lire l'objet chiffré (et mémoriser son ETag) ;
  2. le SAUVEGARDER localement (l'objet reste chiffré) ;
  3. le déchiffrer avec l'ANCIENNE clé (preuve qu'elle est la bonne) ;
  4. re-chiffrer avec la NOUVELLE clé ;
  5. VÉRIFIER que le résultat se déchiffre bien avec la nouvelle clé,
     AVANT toute écriture distante ;
  6. écrire une COPIE horodatée sur S3 (filet de retour arrière) ;
  7. RELIRE et comparer (contenu + ETag) — abandon si l'objet a changé ;
  8. écrire l'objet courant ;
  9. relire et re-vérifier depuis S3.

Aucune clé d'unseal ni valeur de bootstrap n'est affichée.

## Usage

    # Contrôle à blanc (n'écrit rien) — À FAIRE EN PREMIER
    python3 scripts/rotate_bootstrap_key.py --dry-run

    # Rotation réelle (toutes les instances arrêtées)
    python3 scripts/rotate_bootstrap_key.py

L'ancienne clé est lue depuis `ADMIN_BOOTSTRAP_KEY` (ou `--old-key-env NOM`),
la nouvelle depuis `ADMIN_BOOTSTRAP_KEY_NEW` (ou `--new-key-env NOM`).
Jamais en argument de ligne de commande (les arguments fuient dans `ps` et
l'historique du shell).

## APRÈS le script — obligatoire

  1. mettre `ADMIN_BOOTSTRAP_KEY` = nouvelle valeur dans la configuration
     déployée (et la conserver hors dépôt) ;
  2. **tester un redémarrage à froid** : c'est le seul test qui prouve la
     rotation ; sans lui, l'incident n'apparaîtra qu'au prochain arrêt ;
  3. conserver l'ancienne valeur et les copies jusqu'à ce que ce test soit
     concluant.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.openbao.crypto import (  # noqa: E402
    decrypt_with_bootstrap_key,
    encrypt_with_bootstrap_key,
    validate_bootstrap_key,
)

_S3_INIT_KEY = "_init/init_keys.json.enc"


class RotationAborted(RuntimeError):
    """Rotation interrompue — le message porte l'état exact et la conduite à tenir."""


def _ok(message: str) -> None:
    print(f"✅ {message}")


def _read_object(s3, bucket: str) -> tuple:
    """Lit l'objet chiffré. Retourne (contenu_base64, etag)."""
    try:
        response = s3.get_object(Bucket=bucket, Key=_S3_INIT_KEY)
        body = response["Body"].read().decode("ascii")
        return body, response.get("ETag")
    except Exception as exc:
        raise RotationAborted(
            f"Objet chiffré illisible sur s3://{bucket}/{_S3_INIT_KEY} "
            f"({type(exc).__name__}). Rotation annulée, rien n'a été modifié."
        ) from exc


def rotate(s3, bucket: str, old_key: str, new_key: str, *,
           backup_path: str, dry_run: bool, stamp: str) -> dict:
    """
    Exécute la rotation. Lève `RotationAborted` à la première anomalie.

    Séparée de `main()` pour être testable avec un faux client S3 (les
    garanties de ce script — ordre des écritures, abandon sur conflit, dry-run
    qui n'écrit rien — doivent être PROUVÉES, pas seulement documentées).

    Returns:
        {"rollback_key": str|None, "backup_path": str|None}
    """
    # ── 1. Lire l'objet chiffré (+ ETag pour la détection de conflit) ──────
    encrypted_b64, etag = _read_object(s3, bucket)
    _ok(f"Objet chiffré lu ({len(encrypted_b64)} octets base64)")

    # ── 2. Sauvegarde locale AVANT toute opération (objet CHIFFRÉ) ─────────
    written_backup = None
    if dry_run:
        print(f"ℹ️  [dry-run] sauvegarde locale non écrite ({backup_path})")
    else:
        with open(backup_path, "w", encoding="ascii") as fh:
            fh.write(encrypted_b64)
        written_backup = backup_path
        _ok(f"Sauvegarde locale écrite : {backup_path} "
            "(à conserver jusqu'au test de redémarrage à froid)")

    # ── 3. Déchiffrer avec l'ANCIENNE clé ─────────────────────────────────
    try:
        plaintext = decrypt_with_bootstrap_key(encrypted_b64, old_key)
    except Exception as exc:
        raise RotationAborted(
            "Déchiffrement impossible avec l'ancienne clé fournie : ce n'est "
            "pas la clé en vigueur, ou l'objet est corrompu. Rotation annulée, "
            "rien n'a été modifié sur S3."
        ) from exc
    try:
        payload = json.loads(plaintext)
        if not payload.get("keys"):
            raise ValueError("aucune clé d'unseal dans le contenu déchiffré")
    except Exception as exc:
        raise RotationAborted(
            f"Contenu déchiffré inattendu ({exc}) — rotation annulée.") from exc
    _ok(f"Déchiffrement avec l'ancienne clé OK "
        f"({len(payload['keys'])} clé(s) d'unseal)")

    # ── 4-5. Re-chiffrer, puis VÉRIFIER avant toute écriture ──────────────
    re_encrypted = encrypt_with_bootstrap_key(plaintext, new_key)
    try:
        check = decrypt_with_bootstrap_key(re_encrypted, new_key)
    except Exception as exc:
        raise RotationAborted(
            "Le re-chiffrement ne se déchiffre pas avec la nouvelle clé — "
            "rotation annulée, rien n'a été modifié sur S3.") from exc
    if check != plaintext:
        raise RotationAborted(
            "Le contenu re-déchiffré diffère de l'original — rotation annulée, "
            "rien n'a été modifié sur S3.")
    _ok("Vérification locale OK (le nouvel objet se déchiffre avec la nouvelle clé)")

    if dry_run:
        print("\n✅ [dry-run] Séquence vérifiée de bout en bout. "
              "Aucune écriture effectuée.")
        print("   Relancer sans --dry-run pour appliquer la rotation "
              "(toutes les instances arrêtées).")
        return {"rollback_key": None, "backup_path": None}

    # ── 6. Copie horodatée sur S3 (retour arrière possible) ───────────────
    rollback_key = f"{_S3_INIT_KEY}.{stamp}.bak"
    try:
        s3.put_object(Bucket=bucket, Key=rollback_key,
                      Body=encrypted_b64.encode("ascii"))
    except Exception as exc:
        raise RotationAborted(
            f"Copie de retour arrière impossible ({type(exc).__name__}) — "
            "rotation annulée AVANT modification de l'objet courant."
        ) from exc
    _ok(f"Copie de retour arrière : s3://{bucket}/{rollback_key}")

    # ── 7. Détection de conflit : l'objet a-t-il changé entre-temps ? ─────
    # Une instance vivante, une initialisation, une migration legacy ou une
    # autre rotation peut avoir réécrit l'objet depuis l'étape 1. Écraser
    # cette version plus récente ferait perdre des clés dont le volume peut
    # dépendre. On abandonne — sans avoir touché à l'objet courant.
    current_b64, current_etag = _read_object(s3, bucket)
    if current_b64 != encrypted_b64 or (etag and current_etag and current_etag != etag):
        raise RotationAborted(
            "CONFLIT : l'objet chiffré a été modifié depuis le début de la "
            "rotation (une instance tourne encore, ou une autre opération "
            "l'a réécrit). Rotation ABANDONNÉE ; l'objet courant est intact et "
            f"une copie de l'état initial reste dans s3://{bucket}/{rollback_key}. "
            "Arrêter toutes les instances, puis relancer.")
    _ok("Aucun changement concurrent détecté (contenu et ETag identiques)")

    # ── 8. Écrire l'objet courant ─────────────────────────────────────────
    try:
        s3.put_object(Bucket=bucket, Key=_S3_INIT_KEY,
                      Body=re_encrypted.encode("ascii"))
    except Exception as exc:
        raise RotationAborted(
            f"Écriture de l'objet courant échouée ({type(exc).__name__}). "
            f"L'objet d'origine est peut-être intact ; vérifier, et restaurer "
            f"depuis s3://{bucket}/{rollback_key} ou {written_backup} si besoin. "
            "NE PAS réinitialiser le coffre."
        ) from exc
    _ok("Objet courant réécrit avec la nouvelle clé")

    # ── 9. Relire depuis S3 et re-vérifier ────────────────────────────────
    try:
        reread, _ = _read_object(s3, bucket)
        final = decrypt_with_bootstrap_key(reread, new_key)
    except Exception as exc:
        raise RotationAborted(
            f"Relecture/déchiffrement depuis S3 échoué ({type(exc).__name__}) — "
            f"RESTAURER immédiatement depuis s3://{bucket}/{rollback_key}."
        ) from exc
    if final != plaintext:
        raise RotationAborted(
            f"Contenu relu incohérent — RESTAURER depuis "
            f"s3://{bucket}/{rollback_key}.")
    _ok("Relecture depuis S3 vérifiée")

    return {"rollback_key": rollback_key, "backup_path": written_backup}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rotation sûre d'ADMIN_BOOTSTRAP_KEY (issue #121). "
                    "Toutes les instances mcp-vault doivent être ARRÊTÉES.")
    parser.add_argument("--dry-run", action="store_true",
                        help="tout vérifier sans RIEN écrire (S3 ni disque)")
    parser.add_argument("--old-key-env", default="ADMIN_BOOTSTRAP_KEY",
                        help="variable d'environnement portant l'ANCIENNE clé")
    parser.add_argument("--new-key-env", default="ADMIN_BOOTSTRAP_KEY_NEW",
                        help="variable d'environnement portant la NOUVELLE clé")
    parser.add_argument("--backup-dir", default=".",
                        help="répertoire de la sauvegarde locale de l'objet chiffré")
    args = parser.parse_args()

    old_key = os.environ.get(args.old_key_env, "")
    new_key = os.environ.get(args.new_key_env, "")
    if not old_key:
        sys.exit(f"❌ {args.old_key_env} est vide — l'ancienne clé est requise.")
    if not new_key:
        sys.exit(f"❌ {args.new_key_env} est vide — la nouvelle clé est requise.")
    if new_key == old_key:
        sys.exit("❌ La nouvelle clé est identique à l'ancienne — rien à faire.")

    valid, why = validate_bootstrap_key(new_key)
    if not valid:
        sys.exit(f"❌ Nouvelle clé refusée : {why}")

    from mcp_vault.config import get_settings
    settings = get_settings()
    if not (settings.s3_endpoint_url and settings.s3_bucket_name):
        sys.exit("❌ S3 non configuré (S3_ENDPOINT_URL / S3_BUCKET_NAME) — "
                 "aucun objet chiffré à faire tourner.")

    if not args.dry_run:
        print("⚠️  EXÉCUTION EXCLUSIVE REQUISE : toutes les instances mcp-vault "
              "doivent être arrêtées.\n")

    from mcp_vault.s3_client import get_s3_data_client
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    try:
        result = rotate(
            get_s3_data_client(), settings.s3_bucket_name, old_key, new_key,
            backup_path=os.path.join(args.backup_dir,
                                     f"init_keys.json.enc.{stamp}.bak"),
            dry_run=args.dry_run, stamp=stamp,
        )
    except RotationAborted as exc:
        sys.exit(f"❌ {exc}")

    if args.dry_run:
        return

    print("\n✅ Rotation appliquée et vérifiée depuis S3.")
    print("⚠️  À FAIRE MAINTENANT, dans cet ordre :")
    print(f"   1. mettre ADMIN_BOOTSTRAP_KEY = valeur de {args.new_key_env} "
          "dans la configuration déployée (conservée hors dépôt) ;")
    print("   2. TESTER UN REDÉMARRAGE À FROID — seul test qui prouve la rotation ;")
    print(f"   3. conserver l'ancienne clé, {result['backup_path']} et "
          f"s3://{settings.s3_bucket_name}/{result['rollback_key']} "
          "jusqu'à ce que ce test soit concluant.")


if __name__ == "__main__":
    main()
