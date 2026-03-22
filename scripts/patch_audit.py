#!/usr/bin/env python3
"""Script de patch pour intégrer l'audit dans server.py — Phase 8c."""

import re

# Lire server.py
with open("src/mcp_vault/server.py", "r") as f:
    content = f.read()

# 1. Ajouter le helper _r() et l'import time après les imports existants
helper = '''
import time as _time

def _r(tool: str, result: dict, vault_id: str = "", detail: str = "") -> dict:
    """Log audit event and return result."""
    from .audit import log_audit
    status = result.get("status", "?") if isinstance(result, dict) else "?"
    log_audit(tool, status, vault_id, detail)
    return result

'''

# Insérer après "logger = ..."
content = content.replace(
    '# --- FastMCP instance ---',
    helper + '# --- FastMCP instance ---'
)

# 2. Ajouter _r() aux return des outils principaux
# Pattern: pour chaque outil, wraper le return final avec _r()
# On fait ça avec des remplacements ciblés

replacements = [
    # system_health
    ('return {\n        "status": "ok" if all_ok else "degraded",\n        "services": {',
     None),  # Skip system tools (exempt)
    
    # vault_create
    ('    return await create_space(vault_id, description)\n',
     '    return _r("vault_create", await create_space(vault_id, description), vault_id)\n'),
    
    # vault_list - return list_spaces
    ('    return await list_spaces(allowed_vault_ids=allowed_vault_ids)\n',
     '    return _r("vault_list", await list_spaces(allowed_vault_ids=allowed_vault_ids))\n'),
    
    # vault_info
    ('    return await get_space_info(vault_id)\n',
     '    return _r("vault_info", await get_space_info(vault_id), vault_id)\n'),
    
    # vault_update
    ('    return await update_space(vault_id, description)\n',
     '    return _r("vault_update", await update_space(vault_id, description), vault_id)\n'),
    
    # vault_delete
    ('    return await delete_space(vault_id)\n',
     '    return _r("vault_delete", await delete_space(vault_id), vault_id)\n'),
    
    # secret_write
    ('    return await write_secret(vault_id, path, data, secret_type, tags, favorite)\n',
     '    return _r("secret_write", await write_secret(vault_id, path, data, secret_type, tags, favorite), vault_id, path)\n'),
    
    # secret_read
    ('    return await read_secret(vault_id, path, version)\n',
     '    return _r("secret_read", await read_secret(vault_id, path, version), vault_id, path)\n'),
    
    # secret_list
    ('    return await list_secrets(vault_id, path)\n',
     '    return _r("secret_list", await list_secrets(vault_id, path), vault_id)\n'),
    
    # secret_delete
    ('    return await delete_secret(vault_id, path)\n',
     '    return _r("secret_delete", await delete_secret(vault_id, path), vault_id, path)\n'),
    
    # ssh_ca_setup
    ('    return await setup_ssh_ca(vault_id, role_name, allowed_users, default_user, ttl)\n',
     '    return _r("ssh_ca_setup", await setup_ssh_ca(vault_id, role_name, allowed_users, default_user, ttl), vault_id, role_name)\n'),
    
    # ssh_sign_key
    ('    return await sign_ssh_key(vault_id, role_name, public_key, ttl)\n',
     '    return _r("ssh_sign_key", await sign_ssh_key(vault_id, role_name, public_key, ttl), vault_id, role_name)\n'),
    
    # ssh_ca_public_key
    ('    return await get_ca_public_key(vault_id)\n',
     '    return _r("ssh_ca_public_key", await get_ca_public_key(vault_id), vault_id)\n'),
    
    # ssh_ca_list_roles
    ('    return await list_ssh_roles(vault_id)\n',
     '    return _r("ssh_ca_list_roles", await list_ssh_roles(vault_id), vault_id)\n'),
    
    # ssh_ca_role_info
    ('    return await get_ssh_role_info(vault_id, role_name)\n',
     '    return _r("ssh_ca_role_info", await get_ssh_role_info(vault_id, role_name), vault_id, role_name)\n'),
]

for old, new in replacements:
    if new is None:
        continue
    if old in content:
        content = content.replace(old, new, 1)
        print(f"  ✅ Patched: {old[:60].strip()}...")
    else:
        print(f"  ⚠️  Not found: {old[:60].strip()}...")

# Écrire le fichier patché
with open("src/mcp_vault/server.py", "w") as f:
    f.write(content)

print("\n✅ server.py patché avec audit logging")
