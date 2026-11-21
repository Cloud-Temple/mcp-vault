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
    "m8_preflight_hors_coraza": ("Caddyfile", lambda t: _remplacer(
        _remplacer(t, PREFLIGHT_INTERNE, ""),
        "\t# ── Toutes les autres surfaces",
        "\t@cors_preflight method OPTIONS\n\thandle @cors_preflight {\n\t\trespond 204\n\t}\n\n"
        "\t# ── Toutes les autres surfaces")),
}


def main(choix):
    resultats = {}
    for nom in choix or sorted(MUTATIONS):
        fichier, muter = MUTATIONS[nom]
        with tempfile.TemporaryDirectory() as d:
            caddy, coraza = os.path.join(d, "Caddyfile"), os.path.join(d, "coraza.conf")
            open(caddy, "w").write(muter(CADDY) if fichier == "Caddyfile" else CADDY)
            open(coraza, "w").write(muter(CORAZA) if fichier == "coraza.conf" else CORAZA)
            env = dict(os.environ, WAF_CADDYFILE=caddy, WAF_CORAZA_CONF=coraza,
                       BENCH_SUFFIX=f"mut-{nom[:2]}")
            fini = subprocess.run([os.path.join(ICI, "run_bench.sh"), "-q", "--no-header", "-p", "no:randomly"],
                                  env=env, capture_output=True, text=True)
            resume = (fini.stdout.strip().splitlines() or ["?"])[-1]
            resultats[nom] = (fini.returncode != 0, resume)
            print(f"{'MORD ' if fini.returncode else 'VERT!'} {nom:36} {resume}", flush=True)
    rate = [n for n, (mord, _) in resultats.items() if not mord]
    if rate:
        sys.exit(f"mutations NON détectées : {rate}")


if __name__ == "__main__":
    main(sys.argv[1:])
