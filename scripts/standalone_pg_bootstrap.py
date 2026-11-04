"""Chargeur isolé : mêmes Settings applicatives, root_token seul sur pipe privé.

Ne pas appeler directement : standalone_pg_native lance ce sous-processus avec
cwd explicite et environnement nettoyé. Aucun init, unseal, migration legacy,
set_hvac_client ou publication de credentials.
"""

import os
import sys
from pathlib import Path


def load_root(settings_file):
    from dotenv import dotenv_values
    from standalone_pg_files import private_read

    private_read(settings_file)

    path = Path(settings_file).resolve(strict=True)
    if path.name != ".env":
        raise ValueError("Même fichier .env que le serveur requis")
    os.chdir(path.parent)
    for key, value in dotenv_values(path).items():
        if value is not None:
            os.environ[key] = value
    from mcp_vault.config import get_settings

    get_settings.cache_clear()
    get_settings()  # Le même chargeur que l'application, pas de Settings S3 factices.
    from mcp_vault.openbao.lifecycle import _download_encrypted_keys_from_s3

    envelope = _download_encrypted_keys_from_s3()
    if not isinstance(envelope, dict):
        raise TypeError("Bootstrap existant absent")
    root = envelope.pop("root_token", None)
    envelope.clear()  # keys/keys_base64 jetées immédiatement.
    del envelope
    if not isinstance(root, str) or not root:
        raise ValueError("Root natif absent")
    return root


if __name__ == "__main__":
    try:
        # stdout est un pipe parent privé, jamais le journal d'exploitation.
        sys.stdout.write(load_root(sys.argv[1]))
    except Exception:  # noqa: BLE001 - no bootstrap material on stderr
        sys.exit(1)
