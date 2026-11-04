"""Raccord des routes JSON admin à la même frontière d'audit que MCP.

La réponse JSON reste privée jusqu'à la clôture ; les autorisations du routeur
et les transports métier ne sont pas remplacés par ce raccord.
"""
import json
import re

from ..config import get_settings
from ..vault_ids import is_valid_vault_id
from .audit_call import audited_call


def route(scope):
    method, path = scope.get('method'), scope.get('path', '')
    exact = {
        ('GET', '/admin/api/vaults'): 'vault_list',
        ('POST', '/admin/api/vaults'): 'vault_create',
        ('POST', '/admin/api/vaults/metadata-batch'): 'vault_metadata_batch',
        ('GET', '/admin/api/generate-password'): 'secret_generate_password',
        ('POST', '/admin/api/tokens'): 'token_create',
        ('GET', '/admin/api/tokens'): 'token_list',
        ('POST', '/admin/api/tokens/purge'): 'token_purge',
        ('POST', '/admin/api/policies'): 'policy_create',
        ('GET', '/admin/api/policies'): 'policy_list',
        ('POST', '/admin/api/mission-bindings'): 'mission_binding_create',
        ('GET', '/admin/api/mission-bindings'): 'mission_binding_list',
        ('POST', '/admin/api/mission-bindings/purge'): 'mission_binding_purge',
        ('POST', '/admin/api/ssh/operator-access'): 'ssh_request_operator_access',
        ('GET', '/admin/api/ssh/operator-profiles'): 'ssh_operator_access_profiles',
        ('GET', '/admin/api/pki/status'): 'pki_ca_status',
        ('POST', '/admin/api/pki/setup'): 'pki_ca_setup',
        ('POST', '/admin/api/pki/issue'): 'pki_issue_cert',
        ('GET', '/admin/api/pki/roles'): 'pki_ca_list_roles',
        ('GET', '/admin/api/pki/certs'): 'pki_list_certs',
        ('POST', '/admin/api/pki/ca/rotate'): 'pki_ca_rotate_intermediate',
    }
    if (method, path) in exact:
        return exact[method, path], ''
    # Le routeur historique utilise le dernier segment, y compris pour les
    # alias imbriqués : conserver son auth et couvrir les mêmes dispatchs.
    if path.startswith('/admin/api/tokens/'):
        tool = {'PUT': 'token_update', 'DELETE': 'token_revoke'}.get(method)
        return (tool, '') if tool else None
    if re.fullmatch(r'/admin/api/policies/[^/]+', path):
        tool = {'GET': 'policy_get', 'DELETE': 'policy_delete'}.get(method)
        return (tool, '') if tool else None
    if re.fullmatch(r'/admin/api/mission-bindings/[^/]+', path):
        tool = {'GET': 'mission_binding_get', 'DELETE': 'mission_binding_delete'}.get(method)
        return (tool, '') if tool else None
    if re.fullmatch(r'/admin/api/pki/roles/[^/]+', path) and method == 'GET':
        return 'pki_ca_role_info', ''
    if path.startswith('/admin/api/pki/certs/') and path.endswith('/revoke') and method == 'POST':
        return 'pki_revoke_cert', ''
    match = re.fullmatch(r'/admin/api/vaults/([^/]+)(.*)', path)
    if not match:
        return None
    vault_id, tail = match.groups()
    # Une cible invalide est traitée par les gardes existantes ; ne jamais
    # introduire des segments de chemin ou des caractères libres dans l'audit.
    if not is_valid_vault_id(vault_id):
        vault_id = ''
    tool = None
    if not tail:
        tool = {'GET': 'vault_info', 'PUT': 'vault_update', 'DELETE': 'vault_delete'}.get(method)
    elif tail == '/secrets' or tail.startswith('/secrets/'):
        tool = {'GET': 'secret_list' if tail in ('/secrets', '/secrets/') else 'secret_read',
                'POST': 'secret_write', 'DELETE': 'secret_delete'}.get(method)
    elif tail.startswith('/ssh/'):
        tool = {('POST', '/ssh/setup'): 'ssh_ca_setup', ('POST', '/ssh/sign'): 'ssh_sign_key',
                ('GET', '/ssh/ca-key'): 'ssh_ca_public_key', ('GET', '/ssh/roles'): 'ssh_ca_list_roles'}.get((method, tail))
        if method == 'GET' and tail.startswith('/ssh/roles/') and tail != '/ssh/roles/':
            tool = 'ssh_ca_role_info'
    return (tool, vault_id) if tool else None


async def audited_response(scope, receive, send, business):
    selected = route(scope)
    if get_settings().metadata_backend != 'postgres' or selected is None:
        return await business(scope, receive, send)
    tool, coffer = selected
    messages = []
    outcome = None

    async def capture(message):
        # Les endpoints visés sont exclusivement _json_response : pas de SSE,
        # d'export, de logs ni de flux arbitraire mis en attente ici.
        if message['type'] not in {'http.response.start', 'http.response.body'}:
            raise ValueError('audit response not JSON')
        messages.append(message)

    async def execute(vault_id):
        nonlocal outcome
        await business(scope, receive, capture)
        starts = [m for m in messages if m['type'] == 'http.response.start']
        bodies = [m for m in messages if m['type'] == 'http.response.body']
        if len(starts) != 1 or len(bodies) != 1 or bodies[0].get('more_body'):
            raise ValueError('audit response incomplete')
        code = starts[0]['status']
        body = json.loads(bodies[0]['body'])
        status = body.get('status') if isinstance(body, dict) else None
        outcome = {'status': status if 200 <= code < 300 and isinstance(status, str) and status in {
            'ok', 'created', 'updated', 'deleted'} else 'error'}
        if code in (401, 403):
            outcome['error_type'] = 'access_denied'
        return outcome

    execute.__name__ = tool
    result = await audited_call(execute)(coffer)
    if result is outcome:
        for message in messages:
            await send(message)
    else:
        # Ne jamais envoyer le raw_token/secret capturé avant une clôture inconnue.
        await send({'type': 'http.response.start', 'status': 503,
                    'headers': [(b'content-type', b'application/json')]})
        await send({'type': 'http.response.body', 'body': json.dumps(result).encode()})
