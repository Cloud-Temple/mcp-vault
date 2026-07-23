#!/usr/bin/env node
'use strict';

const path = require('path');

const elements = new Map();
function element(id) {
    const value = { id, value: '', textContent: '', innerHTML: '' };
    elements.set(id, value);
    return value;
}
for (const id of [
    'ojProfileId', 'ojTarget', 'ojPrincipal', 'ojTtl',
    'ojPublicKey', 'ojReason', 'ojResult', 'page-dashboard', 'vaultDetail',
]) element(id);

global.document = {
    getElementById: (id) => elements.get(id) || null,
    createElement: () => ({ textContent: '', innerHTML: '' }),
};
global.esc = (value) => String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
global.alert = () => {};
let openedModal = '';
global.openModal = (id) => { openedModal = id; };
global.canWrite = () => true;
global.isAdmin = () => false;
global.fmtDate = () => '';
global.STATE = { clientName: 'operator-christophe', perms: ['read', 'write'] };

const calls = [];
let operatorProfilesDenied = false;
global.api = async (endpoint, options = {}) => {
    calls.push({ endpoint, options });
    if (endpoint === '/ssh/operator-profiles') {
        if (operatorProfilesDenied) throw new Error('policy denied');
        return {
            status: 'ok',
            profiles: [{
                profile_id: 'bastion-prod', vault_id: 'agentic-platform',
                target: 'bastion-01', principal: 'ctadmin', ttl_seconds: 900,
            }],
            count: 1,
        };
    }
    if (endpoint === '/ssh/operator-access') {
        return {
            status: 'ok', target: 'bastion-01', principal: 'ctadmin',
            serial_number: '42', signed_key: 'ssh-cert-public',
        };
    }
    if (endpoint === '/health') return { status: 'ok', tools: [], tools_count: 39 };
    if (endpoint === '/vaults') return { status: 'error', message: 'policy denied' };
    if (endpoint === '/vaults/agentic-platform') {
        return {
            status: 'ok', vault_id: 'agentic-platform', description: 'Vault test',
            ssh_ca_roles: [], has_ssh_ca: false,
        };
    }
    if (endpoint === '/vaults/agentic-platform/secrets') {
        return { status: 'ok', keys: [] };
    }
    if (endpoint === '/tokens') return { status: 'error', message: 'admin required' };
    throw new Error(`endpoint inattendu: ${endpoint}`);
};

const vaultsPath = path.join(__dirname, '..', '..', 'src', 'mcp_vault', 'static', 'js', 'vaults.js');
const { promptOperatorSshAccess, doOperatorSshAccess, selectVault } = require(vaultsPath);
const dashboardPath = path.join(__dirname, '..', '..', 'src', 'mcp_vault', 'static', 'js', 'dashboard.js');
const { loadDashboard } = require(dashboardPath);

function assert(condition, message) {
    if (!condition) throw new Error(message);
}

async function main() {
    await loadDashboard();
    const dashboard = elements.get('page-dashboard').innerHTML;
    assert(dashboard.includes('Accès SSH JIT opérateur'),
        'le JIT doit rester accessible sans permission vault_info');
    assert(dashboard.includes("promptOperatorSshAccess('bastion-prod')"),
        'le profil JIT doit être actionnable depuis le dashboard');

    await promptOperatorSshAccess('bastion-prod');
    assert(openedModal === 'modalOperatorSshAccess', 'le modal JIT doit être ouvert');
    assert(elements.get('ojProfileId').value === 'bastion-prod', 'profile_id non rendu');
    assert(elements.get('ojTarget').textContent === 'bastion-01', 'cible imposée non affichée');
    assert(elements.get('ojPrincipal').textContent === 'ctadmin', 'principal imposé non affiché');
    assert(elements.get('ojTtl').textContent === '900 s', 'TTL imposé non affiché');

    elements.get('ojPublicKey').value = 'ssh-ed25519 AAAATEST';
    elements.get('ojReason').value = 'ticket INC-230';
    await doOperatorSshAccess();

    const request = calls.find((item) => item.endpoint === '/ssh/operator-access');
    assert(request, 'la demande JIT doit appeler la route dédiée');
    assert(request.options.method === 'POST', 'la demande JIT doit être un POST');
    const body = JSON.parse(request.options.body);
    assert(JSON.stringify(Object.keys(body).sort()) === JSON.stringify(['profile_id', 'public_key', 'reason']),
        'le body ne doit contenir que profile_id, public_key et reason');
    assert(body.profile_id === 'bastion-prod', 'profile_id incorrect');
    assert(body.public_key === 'ssh-ed25519 AAAATEST', 'clé publique incorrecte');
    assert(body.reason === 'ticket INC-230', 'motif incorrect');
    for (const forbidden of ['ttl', 'ttl_seconds', 'role_name', 'principal', 'vault_id', 'target']) {
        assert(!(forbidden in body), `attribut de certificat libre interdit: ${forbidden}`);
    }
    assert(elements.get('ojResult').innerHTML.includes('Accès JIT émis'), 'résultat JIT non rendu');

    operatorProfilesDenied = true;
    await selectVault('agentic-platform');
    assert(elements.get('vaultDetail').innerHTML.includes('Vault test'),
        'la fiche Vault standard doit rester utilisable sans policy SSH JIT');
    process.stdout.write('operator SSH JIT UI contract: OK\n');
}

main().catch((error) => {
    console.error(error && error.stack ? error.stack : error);
    process.exit(1);
});
