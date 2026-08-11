#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rotation SÛRE d'ADMIN_BOOTSTRAP_KEY (issue #121).

## Pourquoi ce script existe

`ADMIN_BOOTSTRAP_KEY` chiffre l'objet S3 qui contient les clés d'unseal
d'OpenBao. Changer sa valeur sans re-chiffrer cet objet empêche tout
**redémarrage à froid** : les clés d'unseal ne sont plus déchiffrables, donc le
coffre ne peut plus s'ouvrir. Sans l'ancienne valeur, les secrets sont perdus.

Ce script exécute la seule séquence sûre, dans l'ordre, en s'arrêtant à la
première anomalie :

  1. lire l'objet chiffré actuel et le SAUVEGARDER localement ;
  2. le déchiffrer avec l'ANCIENNE clé (preuve qu'elle est la bonne) ;
  3. re-chiffrer avec la NOUVELLE clé ;
  4. VÉRIFIER que le résultat se déchiffre bien avec la nouvelle clé
     (avant toute écriture distante) ;
  5. écrire une COPIE horodatée sur S3 (filet de retour arrière) ;
  6. écrire l'objet courant ;
  7. relire et re-vérifier depuis S3.

Aucune clé d'unseal ni valeur de bootstrap n'est affichée.

## Usage

    # Contrôle à blanc (n'écrit rien) — À FAIRE EN PREMIER
    python3 scripts/rotate_bootstrap_key.py --dry-run

    # Rotation réelle
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
  3. conserver l'ancienne valeur jusqu'à ce que ce test soit concluant.
"""

import argparse
import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_vault.config import get_settings  # noqa: E402
from mcp_vault.openbao.crypto import (  # noqa: E402
    decrypt_with_bootstrap_key,
    encrypt_with_bootstrap_key,
    validate_bootstrap_key,
)

_S3_INIT_KEY = "_init/init_keys.json.enc"


def _fail(message: str) -> None:
    print(f"❌ {message}", file=sys.stderr)
    sys.exit(1)


def _ok(message: str) -> None:
    print(f"✅ {message}")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Rotation sûre d'ADMIN_BOOTSTRAP_KEY (issue #121)")
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
        _fail(f"{args.old_key_env} est vide — l'ancienne clé est requise.")
    if not new_key:
        _fail(f"{args.new_key_env} est vide — la nouvelle clé est requise.")
    if new_key == old_key:
        _fail("La nouvelle clé est identique à l'ancienne — rien à faire.")

    valid, why = validate_bootstrap_key(new_key)
    if not valid:
        _fail(f"Nouvelle clé refusée : {why}")

    settings = get_settings()
    if not (settings.s3_endpoint_url and settings.s3_bucket_name):
        _fail("S3 non configuré (S3_ENDPOINT_URL / S3_BUCKET_NAME) — "
              "aucun objet chiffré à faire tourner.")

    from mcp_vault.s3_client import get_s3_data_client
    s3 = get_s3_data_client()
    bucket = settings.s3_bucket_name

    # ── 1. Lire l'objet chiffré ────────────────────────────────────────────
    try:
        encrypted_b64 = s3.get_object(Bucket=bucket, Key=_S3_INIT_KEY)["Body"] \
            .read().decode("ascii")
    except Exception as exc:  # NoSuchKey inclus — rien à faire tourner
        _fail(f"Objet chiffré illisible sur s3://{bucket}/{_S3_INIT_KEY} "
              f"({type(exc).__name__}). Rotation annulée, rien n'a été modifié.")
    _ok(f"Objet chiffré lu ({len(encrypted_b64)} octets base64)")

    # ── 2. Sauvegarde locale AVANT toute opération ─────────────────────────
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup_path = os.path.join(args.backup_dir, f"init_keys.json.enc.{stamp}.bak")
    if args.dry_run:
        print(f"ℹ️  [dry-run] sauvegarde locale non écrite ({backup_path})")
    else:
        with open(backup_path, "w", encoding="ascii") as fh:
            fh.write(encrypted_b64)
        _ok(f"Sauvegarde locale écrite : {backup_path} "
            "(à conserver jusqu'au test de redémarrage à froid)")

    # ── 3. Déchiffrer avec l'ANCIENNE clé ─────────────────────────────────
    try:
        plaintext = decrypt_with_bootstrap_key(encrypted_b64, old_key)
    except Exception:
        _fail(f"Déchiffrement impossible avec {args.old_key_env} : ce n'est pas "
              "la clé en vigueur. Rotation annulée, rien n'a été modifié sur S3.")
    try:
        payload = json.loads(plaintext)
        if not payload.get("keys"):
            raise ValueError("aucune clé d'unseal dans le contenu déchiffré")
    except Exception as exc:
        _fail(f"Contenu déchiffré inattendu ({exc}) — rotation annulée.")
    _ok(f"Déchiffrement avec l'ancienne clé OK ({len(payload['keys'])} clé(s) d'unseal)")

    # ── 4. Re-chiffrer, puis VÉRIFIER avant d'écrire ──────────────────────
    re_encrypted = encrypt_with_bootstrap_key(plaintext, new_key)
    try:
        check = decrypt_with_bootstrap_key(re_encrypted, new_key)
    except Exception:
        _fail("Le re-chiffrement ne se déchiffre pas avec la nouvelle clé — "
              "rotation annulée, rien n'a été modifié sur S3.")
    if check != plaintext:
        _fail("Le contenu re-déchiffré diffère de l'original — "
              "rotation annulée, rien n'a été modifié sur S3.")
    _ok("Vérification locale OK (le nouvel objet se déchiffre avec la nouvelle clé)")

    if args.dry_run:
        print("\n✅ [dry-run] Séquence vérifiée de bout en bout. "
              "Aucune écriture effectuée.")
        print("   Relancer sans --dry-run pour appliquer la rotation.")
        return

    # ── 5. Copie horodatée sur S3 (retour arrière possible) ───────────────
    rollback_key = f"{_S3_INIT_KEY}.{stamp}.bak"
    try:
        s3.put_object(Bucket=bucket, Key=rollback_key,
                      Body=encrypted_b64.encode("ascii"))
    except Exception as exc:
        _fail(f"Copie de retour arrière impossible ({type(exc).__name__}) — "
              "rotation annulée avant modification de l'objet courant.")
    _ok(f"Copie de retour arrière : s3://{bucket}/{rollback_key}")

    # ── 6. Écrire l'objet courant ─────────────────────────────────────────
    try:
        s3.put_object(Bucket=bucket, Key=_S3_INIT_KEY,
                      Body=re_encrypted.encode("ascii"))
    except Exception as exc:
        _fail(f"Écriture de l'objet courant échouée ({type(exc).__name__}). "
              f"L'objet d'origine est peut-être intact ; vérifier, et restaurer "
              f"depuis s3://{bucket}/{rollback_key} ou {backup_path} si besoin. "
              "NE PAS réinitialiser le coffre.")
    _ok("Objet courant réécrit avec la nouvelle clé")

    # ── 7. Relire depuis S3 et re-vérifier ────────────────────────────────
    try:
        reread = s3.get_object(Bucket=bucket, Key=_S3_INIT_KEY)["Body"] \
            .read().decode("ascii")
        final = decrypt_with_bootstrap_key(reread, new_key)
    except Exception as exc:
        _fail(f"Relecture/déchiffrement depuis S3 échoué ({type(exc).__name__}) — "
              f"RESTAURER immédiatement depuis s3://{bucket}/{rollback_key}.")
    if final != plaintext:
        _fail(f"Contenu relu incohérent — RESTAURER depuis "
              f"s3://{bucket}/{rollback_key}.")

    print("\n✅ Rotation appliquée et vérifiée depuis S3.")
    print("⚠️  À FAIRE MAINTENANT, dans cet ordre :")
    print(f"   1. mettre ADMIN_BOOTSTRAP_KEY = valeur de {args.new_key_env} "
          "dans la configuration déployée (conservée hors dépôt) ;")
    print("   2. TESTER UN REDÉMARRAGE À FROID — seul test qui prouve la rotation ;")
    print(f"   3. conserver l'ancienne clé, {backup_path} et "
          f"s3://{bucket}/{rollback_key} jusqu'à ce que ce test soit concluant.")


if __name__ == "__main__":
    main()
