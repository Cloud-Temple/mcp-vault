"""Preuves par mutation du banc WAF (#118).

Chaque mutation retire UNE propriété de la configuration livrée ; le banc
(`run_bench.sh`) doit alors échouer. Une mutation qui laisse le banc vert
signale un test qui n'exerce pas ce qu'il prétend. Usage local, hors CI :

    python3 waf/tests/mutations.py            # toutes
    python3 waf/tests/mutations.py m3 m5      # une sélection

Chaque mutation vérifie d'abord qu'elle MORD sur le texte (remplacement
effectivement appliqué) : une mutation sans effet serait un faux vert.
"""
import os
import subprocess
import sys
import tempfile

ICI = os.path.dirname(os.path.abspath(__file__))
WAF = os.path.dirname(ICI)
CADDY = open(os.path.join(WAF, "Caddyfile")).read()
CORAZA = open(os.path.join(WAF, "coraza.conf")).read()

PREFLIGHT_INTERNE = CADDY[CADDY.index("\t\t# ── CORS restrictif (P2-6)"):CADDY.index("\t\treverse_proxy mcp-vault:8030 {\n\t\t\timport mcp_vault_backend_options\n\t\t}\n\t}\n\n\t# Un refus")]


def _remplacer(texte, avant, apres):
    if avant not in texte:
        raise SystemExit(f"mutation sans effet : motif introuvable {avant[:60]!r}")
    return texte.replace(avant, apres, 1)


MUTATIONS = {
    "m1_coraza_sur_mcp": ("Caddyfile", lambda t: _remplacer(
        t, "\t\thandle @mcp_methods {\n",
        "\t\thandle @mcp_methods {\n\t\t\tcoraza_waf {\n\t\t\t\tdirectives `\n"
        "\t\t\t\t\tInclude /etc/coraza/coraza.conf\n\t\t\t\t`\n\t\t\t}\n")),
    "m2_sous_chemins_oublies": ("Caddyfile", lambda t: _remplacer(
        t, "^/mcp(?:/[A-Za-z0-9_~-][A-Za-z0-9._~-]*)*/?(?:\\\\?.*)?$", "^/mcp(?:\\\\?.*)?$")),
    "m3_sans_refus_content_length": ("Caddyfile", lambda t: _remplacer(
        t, "\t\thandle @mcp_too_large {\n\t\t\trespond 413\n\t\t}\n", "")),
    "m4_exclusion_json_residuelle": ("coraza.conf", lambda t: t + (
        '\nSecRuleUpdateTargetById 930120 "!ARGS:/^json\\.params\\.arguments\\.data\\./"\n'
        'SecRuleUpdateTargetById 930120 "!ARGS_NAMES:/^json\\.params\\._meta\\./"\n')),
    "m5_cible_decodee_au_lieu_de_brute": ("Caddyfile", lambda t: _remplacer(
        t, "{http.request.orig_uri}.matches", "{http.request.uri}.matches")),
    "m6_put_autorise": ("Caddyfile", lambda t: _remplacer(
        t, "@mcp_methods method GET POST DELETE OPTIONS", "@mcp_methods method GET POST DELETE OPTIONS PUT")),
    "m7_variantes_sans_borne": ("coraza.conf", lambda t: _remplacer(
        t, "     ctl:requestBodyLimit=65536\"", "     nolog\"")),
    "m9_borne_sur_cible_brute": ("coraza.conf", lambda t: _remplacer(
        t, 'SecRule REQUEST_FILENAME "@rx ^/mcp(?:[/;]|$)" \\\n    "id:10008,phase:1,pass,nolog,\\\n     t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,',
        'SecRule REQUEST_URI "@rx ^/mcp(?:[/?]|$)" \\\n    "id:10008,phase:1,pass,nolog,\\\n     t:none,')),
    "m8_preflight_hors_coraza": ("Caddyfile", lambda t: _remplacer(
        _remplacer(t, PREFLIGHT_INTERNE, ""),
        "\t# ── Toutes les autres surfaces",
        "\t@cors_preflight method OPTIONS\n\thandle @cors_preflight {\n\t\trespond 204\n\t}\n\n"
        "\t# ── Toutes les autres surfaces")),
}


def _banc(caddy_txt, coraza_txt, suffixe):
    """Exécute le banc et rend (code, nb_échecs, nb_succès, nb_erreurs, résumé)."""
    import re
    with tempfile.TemporaryDirectory() as d:
        caddy, coraza = os.path.join(d, "Caddyfile"), os.path.join(d, "coraza.conf")
        open(caddy, "w").write(caddy_txt)
        open(coraza, "w").write(coraza_txt)
        env = dict(os.environ, WAF_CADDYFILE=caddy, WAF_CORAZA_CONF=coraza,
                   BENCH_SUFFIX=suffixe)
        fini = subprocess.run([os.path.join(ICI, "run_bench.sh"), "-q", "--no-header"],
                              env=env, capture_output=True, text=True)
    resume = (fini.stdout.strip().splitlines() or ["?"])[-1]

    def nombre(mot):
        m = re.search(rf"(\d+) {mot}", resume)
        return int(m.group(1)) if m else 0
    return fini.returncode, nombre("failed"), nombre("passed"), nombre("error"), resume


def main(choix):
    # Référence : la configuration livrée, montée comme les mutations, doit
    # être verte. Sinon un échec de mutation ne prouverait rien.
    code, echecs, succes, erreurs, resume = _banc(CADDY, CORAZA, "mut-ref")
    if code or echecs or erreurs or not succes:
        sys.exit(f"référence non verte, mutations non interprétables : {resume}")
    print(f"REF   configuration livrée                 {resume}", flush=True)
    rate = []
    for nom in choix or sorted(MUTATIONS):
        fichier, muter = MUTATIONS[nom]
        code, echecs, succes, erreurs, resume = _banc(
            muter(CADDY) if fichier == "Caddyfile" else CADDY,
            muter(CORAZA) if fichier == "coraza.conf" else CORAZA, f"mut-{nom[:2]}")
        # Seul un échec d'ASSERTION exécutée compte. Une panne Docker, une
        # configuration refusée ou une erreur de collecte ne prouve rien.
        mord = code != 0 and echecs >= 1 and erreurs == 0 and succes >= 1
        etat = "MORD " if mord else ("INFRA" if code and not echecs else "VERT!")
        print(f"{etat} {nom:36} {resume}", flush=True)
        if not mord:
            rate.append(nom)
    if rate:
        sys.exit(f"mutations NON détectées ou non interprétables : {rate}")


if __name__ == "__main__":
    main(sys.argv[1:])
