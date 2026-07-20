/* Fixture FIGÉE — copie exacte de l'ancienne implémentation de toggleSecret()
 * AVANT le correctif de masquage des secrets (issue agentic-platform, 2026-07-20,
 * commit de référence 4039a59 = HEAD juste avant ce correctif).
 *
 * NE JAMAIS mettre à jour ce fichier suite à un changement de vaults.js : il sert
 * de preuve historique, permanente, que le bug existait (isHidden ne masquait que
 * la couleur, la valeur brute était toujours injectée en clair dans le DOM).
 * Exécutée via `vm` (module Node natif, aucune dépendance) dans
 * secret_visibility_contract.test.js, car le code d'origine n'exportait rien en
 * CommonJS — un simple require() ne peut donc pas le charger. Un `require()` de
 * l'ANCIEN fichier ne prouverait rien (il n'exposait aucune fonction) : cette
 * fixture est le seul moyen de rejouer authentiquement le comportement d'origine
 * et de prouver un RED réel (pas un RED accidentel par "fonction introuvable"). */
async function toggleSecret(vaultId, secretPath, elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!el.classList.contains('hidden')) { el.classList.add('hidden'); return; }

    el.innerHTML = '<div class="secret-detail">Chargement…</div>';
    el.classList.remove('hidden');

    const data = await api(`/vaults/${vaultId}/secrets/${secretPath}`);
    if (data.status !== 'ok') {
        el.innerHTML = `<div class="secret-detail" style="color:var(--danger)">Erreur : ${esc(data.message)}</div>`;
        return;
    }

    const secretData = data.data || {};
    const lines = Object.entries(secretData).map(([k, v]) => {
        const isHidden = k === 'password' || k === 'private_key' || k === 'secret' || k === 'cvv' || k === 'seed_phrase';
        return `<span style="color:var(--muted)">${esc(k)}</span>: <span style="color:${isHidden ? 'var(--warning)' : 'var(--text)'}">${esc(String(v))}</span>`;
    });

    el.innerHTML = `<div class="secret-detail">
        <div style="margin-bottom:0.4rem;font-size:0.7rem;color:var(--muted)">Version ${data.version} — ${fmtDate(data.created_time)}</div>
        ${lines.join('\n')}
    </div>`;
}
