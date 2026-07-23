# -*- coding: utf-8 -*-
"""
Fonctions d'affichage Rich — MCP Vault.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.syntax import Syntax

console = Console()


# =============================================================================
# Utilitaires communs
# =============================================================================

def show_error(msg: str):
    console.print(f"[red]❌ {msg}[/red]")

def show_success(msg: str):
    console.print(f"[green]✅ {msg}[/green]")

def show_warning(msg: str):
    console.print(f"[yellow]⚠️  {msg}[/yellow]")

def show_json(data: dict):
    import json
    console.print(Syntax(json.dumps(data, indent=2, ensure_ascii=False), "json"))


# =============================================================================
# system_health
# =============================================================================

def show_health_result(result: dict):
    status = result.get("status", "?")
    icon = "✅" if status == "ok" else "⚠️" if status == "degraded" else "❌"
    info = f"{icon} [bold]MCP Vault[/bold] — Status: [green]{status}[/green]"

    services = result.get("services", {})
    if services:
        for name, svc in services.items():
            svc_icon = "✅" if svc.get("status") == "ok" else "❌"
            info += f"\n  {svc_icon} {name}: {svc.get('detail', '?')}"

    console.print(Panel.fit(
        info,
        border_style="green" if status == "ok" else "yellow",
    ))


# =============================================================================
# system_about
# =============================================================================

def show_about_result(result: dict):
    name = result.get("service", "?")
    version = result.get("version", "?")
    py_version = result.get("python", "?")
    tools_count = result.get("tools_count", 0)
    openbao = result.get("openbao_addr", "?")

    console.print(Panel.fit(
        f"[bold]Service  :[/bold] [cyan]{name}[/cyan]\n"
        f"[bold]Version  :[/bold] [green]{version}[/green]\n"
        f"[bold]Python   :[/bold] {py_version}\n"
        f"[bold]OpenBao  :[/bold] {openbao}\n"
        f"[bold]Outils   :[/bold] {tools_count}",
        title="🔐 À propos",
        border_style="blue",
    ))


# =============================================================================
# system_whoami
# =============================================================================

def show_whoami_result(result: dict):
    status = result.get("status", "?")
    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    client = result.get("client_name", "?")
    auth_type = result.get("auth_type", "?")
    perms = result.get("permissions", [])
    resources = result.get("allowed_resources", [])

    perms_str = ", ".join(perms) if perms else "(aucune)"
    resources_str = ", ".join(resources) if resources else "(tous — isolation par propriétaire)"
    policy_id = result.get("policy_id", "")

    auth_icon = "🔑" if auth_type == "bootstrap" else "🎫"

    info = (
        f"[bold]Client      :[/bold] [cyan]{client}[/cyan]\n"
        f"[bold]Auth        :[/bold] {auth_icon} {auth_type}\n"
        f"[bold]Permissions :[/bold] [green]{perms_str}[/green]\n"
        f"[bold]Vaults      :[/bold] {resources_str}"
    )
    if policy_id:
        info += f"\n[bold]Policy      :[/bold] [yellow]{policy_id}[/yellow]"

    console.print(Panel.fit(info, title="👤 Identité du token", border_style="blue"))


# =============================================================================
# Vault Spaces
# =============================================================================

def show_vault_result(result: dict):
    status = result.get("status", "?")

    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    # --- CREATE ---
    if status == "created":
        show_success(f"Vault [cyan]{result.get('vault_id', '?')}[/cyan] créé")
        if result.get("description"):
            console.print(f"  Description : {result['description']}")
        return

    # --- DELETE ---
    if status == "deleted":
        show_success(f"Vault [cyan]{result.get('vault_id', '?')}[/cyan] supprimé")
        return

    # --- LIST ---
    vaults = result.get("vaults")
    if vaults is not None:
        console.print(f"\n✅ [bold]{len(vaults)} vault(s)[/bold]")
        if vaults:
            table = Table(show_header=True)
            table.add_column("Vault ID", style="cyan bold", min_width=20)
            table.add_column("Description", style="dim")
            table.add_column("Owner", style="blue")
            table.add_column("Secrets", style="green", justify="right")
            for s in vaults:
                table.add_row(
                    s.get("vault_id", "?"),
                    s.get("description", ""),
                    s.get("created_by", ""),
                    str(s.get("secrets_count", "?")),
                )
            console.print(table)
        return

    # --- INFO ---
    if "vault_id" in result:
        sid = result.get("vault_id", "?")
        console.print(f"\n✅ [bold]Vault : {sid}[/bold]")
        console.print(f"  Description : {result.get('description', '(aucune)')}")
        console.print(f"  Secrets     : [green]{result.get('secrets_count', '?')}[/green]")
        return

    # --- Fallback ---
    show_json(result)


# =============================================================================
# Secrets
# =============================================================================

def show_secret_result(result: dict):
    status = result.get("status", "?")

    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    # --- DELETE ---
    if status == "deleted":
        show_success(f"Secret [cyan]{result.get('path', '?')}[/cyan] supprimé")
        return

    # --- READ (a "data" dict) ---
    data = result.get("data")
    if data is not None:
        path = result.get("path", "?")
        version = result.get("version", "?")
        secret_type = data.get("_type", "custom")
        console.print(f"\n✅ [bold]{path}[/bold] (v{version}, type={secret_type})")

        table = Table(show_header=True)
        table.add_column("Champ", style="cyan bold", min_width=15)
        table.add_column("Valeur", style="white")
        for k, v in data.items():
            if k.startswith("_"):
                continue  # Skip metadata
            # Masquer les mots de passe par défaut
            val_str = str(v)
            if "password" in k.lower() or "secret" in k.lower() or "key" in k.lower():
                val_str = val_str[:3] + "•" * (len(val_str) - 3) if len(val_str) > 3 else "•••"
            table.add_row(k, val_str)

        # Show metadata
        for k, v in data.items():
            if k.startswith("_"):
                table.add_row(f"[dim]{k}[/dim]", f"[dim]{v}[/dim]")
        console.print(table)
        return

    # --- WRITE (status=ok, no "data" key, has "version") ---
    if status == "ok" and "version" in result and "path" in result:
        show_success(
            f"Secret [cyan]{result.get('path', '?')}[/cyan] "
            f"écrit (v{result.get('version', '?')}, type={result.get('type', '?')})"
        )
        return

    # --- LIST ---
    keys = result.get("keys")
    if keys is not None:
        vid = result.get("vault_id", "?")
        console.print(f"\n✅ [bold]{len(keys)} clé(s)[/bold] dans [cyan]{vid}[/cyan]")
        if keys:
            for k in keys:
                console.print(f"  📄 {k}")
        return

    # --- Fallback ---
    show_json(result)


# =============================================================================
# Secret Types & Password Generator
# =============================================================================

def show_types_result(result: dict):
    types = result.get("types", [])
    console.print(f"\n✅ [bold]{len(types)} type(s) de secrets[/bold]\n")
    table = Table(show_header=True)
    table.add_column("Type", style="cyan bold", min_width=15)
    table.add_column("Champs requis", style="green")
    table.add_column("Champs optionnels", style="dim")
    for t in types:
        table.add_row(
            t.get("type", "?"),
            ", ".join(t.get("required", [])),
            ", ".join(t.get("optional", [])),
        )
    console.print(table)


def show_password_result(result: dict):
    if result.get("status") != "ok":
        show_error(result.get("message", "Erreur"))
        return
    pw = result.get("password", "?")
    length = result.get("length", "?")
    console.print(Panel.fit(
        f"[bold yellow]{pw}[/bold yellow]",
        title=f"🔑 Mot de passe ({length} chars)",
        border_style="yellow",
    ))


# =============================================================================
# SSH CA
# =============================================================================

def show_ssh_result(result: dict):
    status = result.get("status", "?")
    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    profiles = result.get("profiles")
    if isinstance(profiles, list):
        console.print(f"\n✅ [bold]{result.get('count', len(profiles))} profil(s) SSH JIT disponible(s)[/bold]")
        for profile in profiles:
            console.print(
                f"  🔐 [cyan]{profile.get('profile_id', '?')}[/cyan] → "
                f"{profile.get('target', '?')} / {profile.get('principal', '?')} "
                f"({profile.get('ttl_seconds', '?')}s)"
            )
        return

    # CA Setup (setup retourne vault_id + role_name + mount_point)
    if "role_name" in result and "mount_point" in result:
        show_success(
            f"SSH CA configurée — vault [cyan]{result.get('vault_id', '?')}[/cyan] "
            f"rôle [green]{result.get('role_name', '?')}[/green]"
        )
        console.print(f"  Mount     : {result.get('mount_point', '?')}")
        console.print(f"  Users     : {result.get('allowed_users', '?')}")
        console.print(f"  Default   : {result.get('default_user', '?')}")
        console.print(f"  TTL       : {result.get('ttl', '?')}")
        return

    # Sign key
    signed = result.get("signed_key")
    if signed:
        context = ""
        if result.get("profile_id"):
            context = f" — {result.get('target', '?')} / {result.get('principal', '?')}"
        show_success(f"Clé signée (TTL: {result.get('ttl', '?')}, serial: {result.get('serial_number', '?')}){context}")
        displayed = signed if result.get("profile_id") else (
            signed[:200] + "..." if len(signed) > 200 else signed
        )
        console.print(Panel(
            displayed,
            title="Certificat SSH",
            border_style="green",
        ))
        return

    # List roles
    roles = result.get("roles")
    if roles is not None and "vault_id" in result and "count" in result:
        vid = result.get("vault_id", "?")
        console.print(f"\n✅ [bold]{result.get('count', 0)} rôle(s) SSH CA[/bold] dans [cyan]{vid}[/cyan]")
        if roles:
            for role in roles:
                console.print(f"  🔏 {role}")
        else:
            console.print("  [dim](aucun rôle configuré)[/dim]")
        return

    # Role info
    if "role_name" in result and "key_type" in result:
        console.print(f"\n✅ [bold]Rôle SSH : {result.get('role_name', '?')}[/bold] "
                       f"(vault: [cyan]{result.get('vault_id', '?')}[/cyan])")
        table = Table(show_header=True)
        table.add_column("Paramètre", style="cyan bold", min_width=25)
        table.add_column("Valeur", style="white")
        table.add_row("key_type", str(result.get("key_type", "")))
        table.add_row("ttl", str(result.get("ttl", "")))
        table.add_row("max_ttl", str(result.get("max_ttl", "")))
        table.add_row("default_user", str(result.get("default_user", "")))
        table.add_row("allowed_users", str(result.get("allowed_users", "")))
        table.add_row("allowed_extensions", str(result.get("allowed_extensions", "")))
        table.add_row("allow_user_certificates", str(result.get("allow_user_certificates", "")))
        table.add_row("allow_host_certificates", str(result.get("allow_host_certificates", "")))
        console.print(table)
        return

    # CA public key
    pub_key = result.get("ca_public_key") or result.get("public_key")
    if pub_key:
        console.print(Panel(pub_key, title="Clé publique CA", border_style="cyan"))
        if result.get("usage"):
            console.print(f"  [dim]💡 {result['usage']}[/dim]")
        return

    show_json(result)


# =============================================================================
# Audit Log
# =============================================================================

def show_audit_result(result: dict):
    status = result.get("status", "?")

    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    entries = result.get("entries", [])
    stats = result.get("stats", {})
    total = result.get("total_in_buffer", 0)

    # Stats header
    by_cat = stats.get("by_category", {})
    if by_cat:
        cat_parts = []
        cat_icons = {"system": "⚙️", "vault": "🏛️", "secret": "🔑", "ssh": "🔏",
                     "policy": "📋", "token": "🎫", "audit": "📊"}
        for cat, count in by_cat.items():
            icon = cat_icons.get(cat, "📌")
            cat_parts.append(f"{icon} {cat}:{count}")
        console.print(f"\n[bold]📊 Audit[/bold] — {total} événements total — {' '.join(cat_parts)}")
    else:
        console.print(f"\n[bold]📊 Audit[/bold] — {total} événements total")

    if not entries:
        console.print("  [dim](aucun événement)[/dim]")
        return

    console.print(f"  Affichage : {len(entries)} entrée(s)\n")

    table = Table(show_header=True, show_lines=False, pad_edge=False)
    table.add_column("Heure", style="dim", min_width=8)
    table.add_column("Cat", style="cyan", min_width=6)
    table.add_column("Outil", style="bold white", min_width=18)
    table.add_column("Client", style="blue", min_width=10)
    table.add_column("Vault", style="green", min_width=12)
    table.add_column("Status", min_width=8)
    table.add_column("Détail", style="dim", max_width=30)

    status_styles = {
        "ok": "[green]OK[/green]",
        "created": "[green]CREATED[/green]",
        "deleted": "[yellow]DELETED[/yellow]",
        "updated": "[cyan]UPDATED[/cyan]",
        "error": "[red]ERROR[/red]",
        "denied": "[red bold]DENIED[/red bold]",
    }

    for e in entries:
        ts = (e.get("ts", "") or "")[11:19]
        cat = e.get("category", "?")
        tool = e.get("tool", "?")
        client = e.get("client", "")
        vault = e.get("vault_id", "")
        st = status_styles.get(e.get("status", ""), e.get("status", "?"))
        detail = e.get("detail", "")
        if len(detail) > 40:
            detail = detail[:37] + "..."

        table.add_row(ts, cat, tool, client, vault, st, detail)

    console.print(table)


# =============================================================================
# Policies
# =============================================================================

def show_policy_result(result: dict):
    status = result.get("status", "?")

    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    # --- CREATE ---
    if status == "created" and "policy_id" in result:
        show_success(f"Policy [cyan]{result.get('policy_id', '?')}[/cyan] créée")
        if result.get("description"):
            console.print(f"  Description   : {result['description']}")
        at = result.get("allowed_tools", [])
        dt = result.get("denied_tools", [])
        pr = result.get("path_rules", [])
        if at:
            console.print(f"  Allowed tools : [green]{', '.join(at)}[/green]")
        if dt:
            console.print(f"  Denied tools  : [red]{', '.join(dt)}[/red]")
        if pr:
            console.print(f"  Path rules    : {len(pr)} règle(s)")
        return

    # --- DELETE ---
    if status == "deleted" and "policy_id" in result:
        show_success(f"Policy [cyan]{result.get('policy_id', '?')}[/cyan] supprimée")
        return

    # --- LIST ---
    policies = result.get("policies")
    if policies is not None:
        console.print(f"\n✅ [bold]{len(policies)} policy(ies)[/bold]")
        if policies:
            table = Table(show_header=True)
            table.add_column("Policy ID", style="cyan bold", min_width=20)
            table.add_column("Description", style="dim")
            table.add_column("Allowed", style="green", justify="right")
            table.add_column("Denied", style="red", justify="right")
            table.add_column("Rules", style="white", justify="right")
            table.add_column("Créé par", style="dim")
            for p in policies:
                table.add_row(
                    p.get("policy_id", "?"),
                    p.get("description", ""),
                    str(p.get("allowed_tools_count", 0)),
                    str(p.get("denied_tools_count", 0)),
                    str(p.get("path_rules_count", 0)),
                    p.get("created_by", ""),
                )
            console.print(table)
        return

    # --- GET (détail complet) ---
    if "policy_id" in result and "allowed_tools" in result:
        pid = result.get("policy_id", "?")
        console.print(f"\n✅ [bold]Policy : {pid}[/bold]")
        console.print(f"  Description : {result.get('description', '(aucune)')}")
        console.print(f"  Créé par    : {result.get('created_by', '?')}")
        console.print(f"  Créé le     : {result.get('created_at', '?')}")

        at = result.get("allowed_tools", [])
        dt = result.get("denied_tools", [])
        pr = result.get("path_rules", [])

        if at:
            console.print(f"\n  [green]✅ Allowed tools ({len(at)}):[/green]")
            for t in at:
                console.print(f"    • {t}")
        else:
            console.print(f"\n  [dim]Allowed tools : (tous autorisés)[/dim]")

        if dt:
            console.print(f"\n  [red]🚫 Denied tools ({len(dt)}):[/red]")
            for t in dt:
                console.print(f"    • {t}")

        if pr:
            console.print(f"\n  📋 Path rules ({len(pr)}):")
            for rule in pr:
                vp = rule.get("vault_pattern", "?")
                perms = ", ".join(rule.get("permissions", []))
                ap = rule.get("allowed_paths", [])
                console.print(f"    [cyan]{vp}[/cyan] → permissions: [green]{perms}[/green]")
                if ap:
                    console.print(f"      allowed_paths: [yellow]{', '.join(ap)}[/yellow]")
                else:
                    console.print(f"      allowed_paths: [dim](tous les chemins)[/dim]")
        else:
            console.print(f"\n  [dim]Path rules : (aucune restriction par chemin)[/dim]")
        return

    # --- UPDATE token with policy ---
    if status == "updated":
        show_success(f"Token [cyan]{result.get('client_name', result.get('hash_prefix', '?'))}[/cyan] mis à jour")
        for f in result.get("updated_fields", []):
            console.print(f"  ✏️  {f} → {result.get(f, '?')}")
        return

    show_json(result)


# =============================================================================
# Token management
# =============================================================================

def show_token_result(result: dict):
    status = result.get("status", "?")

    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    # --- CREATE ---
    if "raw_token" in result:
        raw_token = result.get("raw_token", "")
        client_name = result.get("client_name", "?")
        console.print(f"\n✅ [bold]Token créé pour '{client_name}'[/bold]")
        console.print(Panel.fit(
            f"[bold yellow]{raw_token}[/bold yellow]",
            title="⚠️  TOKEN (sauvegardez-le maintenant !)",
            border_style="yellow",
        ))
        console.print(f"  Client      : [cyan]{client_name}[/cyan]")
        email = result.get("email", "")
        if email:
            console.print(f"  Email       : [cyan]{email}[/cyan]")
        console.print(f"  Permissions : [green]{', '.join(result.get('permissions', []))}[/green]")
        resources = result.get("allowed_resources", [])
        if resources:
            console.print(f"  Vaults      : [cyan]{', '.join(resources)}[/cyan]")
        else:
            console.print(f"  Vaults      : [dim](tous — isolation par propriétaire)[/dim]")
        policy = result.get("policy_id", "")
        if policy:
            console.print(f"  Policy      : [yellow]{policy}[/yellow]")
        console.print(f"  Expire      : {result.get('expires_at') or 'jamais'}")
        return

    # --- LIST ---
    tokens = result.get("tokens")
    if tokens is not None:
        console.print(f"\n✅ [bold]{len(tokens)} token(s)[/bold]")
        if tokens:
            table = Table(show_header=True)
            table.add_column("Client", style="cyan bold", min_width=15)
            table.add_column("Permissions", style="green")
            table.add_column("Vaults", style="white")
            table.add_column("Policy", style="yellow")
            table.add_column("Créé le", style="dim")
            table.add_column("Statut", min_width=10)
            table.add_column("Hash", style="dim")
            for t in tokens:
                allowed_vaults = ", ".join(t.get("allowed_resources", [])) or "(owner)"
                policy = t.get("policy_id", "") or ""

                # Date de création
                created = t.get("created_at", "")
                created_str = created[:10] if created else ""

                # Statut avec date de révocation ou d'expiration
                if t.get("revoked"):
                    revoked_at = t.get("revoked_at", "")
                    revoked_str = revoked_at[:10] if revoked_at else ""
                    status_str = f"[red]RÉVOQUÉ[/red]" + (f" {revoked_str}" if revoked_str else "")
                elif t.get("expired"):
                    exp = t.get("expires_at", "")[:10]
                    status_str = f"[yellow]EXPIRÉ[/yellow] {exp}"
                else:
                    exp = t.get("expires_at") or "jamais"
                    if exp != "jamais":
                        exp = exp[:10]
                    status_str = f"[green]actif[/green] → {exp}"

                table.add_row(
                    t.get("client_name", "?"),
                    ", ".join(t.get("permissions", [])),
                    allowed_vaults,
                    policy,
                    created_str,
                    status_str,
                    t.get("hash_prefix", "?"),
                )
            console.print(table)
        return

    # --- REVOKE ---
    if result.get("message"):
        show_success(result["message"])
        return

    show_json(result)


# =============================================================================
# PKI Certificate Authority
# =============================================================================

def show_wrap_result(result: dict):
    """Affichage des opérations JIT broker (wrap / revoke-wrap / wrap-lookup)."""
    status = result.get("status", "?")
    if status == "error":
        show_error(result.get("message", "Erreur wrap broker"))
        return

    # --- WRAP : retourne un wrap_token SENSIBLE ---
    if "wrap_token" in result:
        show_success("Wrap token créé (single-use)")
        table = Table(show_header=False)
        table.add_column("Champ", style="cyan bold", min_width=20)
        table.add_column("Valeur")
        table.add_row("wrap_token ⚠️", f"[yellow]{result.get('wrap_token', '')}[/yellow]")
        table.add_row("accessor",     result.get("accessor", "?"))
        table.add_row("operation_id", result.get("operation_id", "?"))
        table.add_row("mission_id",   result.get("mission_id", "?"))
        table.add_row("expires_at",   result.get("expires_at", "?"))
        if result.get("intended_use"):
            table.add_row("intended_use", result.get("intended_use"))
        console.print(table)
        console.print("[dim]⚠️  wrap_token SENSIBLE — single-use, ne pas logguer.[/dim]")
        return

    # --- REVOKE / LOOKUP : retourne un state ---
    state = result.get("state")
    if state is not None:
        show_success(f"État : [cyan]{state}[/cyan]")
        if "count_revoked" in result or "entries_found" in result:
            table = Table(show_header=False)
            table.add_column("Champ", style="cyan bold", min_width=20)
            table.add_column("Valeur")
            if "entries_found" in result:
                table.add_row("entries_found", str(result.get("entries_found")))
            if "count_revoked" in result:
                table.add_row("count_revoked", str(result.get("count_revoked")))
            console.print(table)
        # Toujours remonter la note (ex : "registry indisponible — révocation
        # impossible") même sur un state ok/not_found — sinon l'opérateur croit
        # à un succès complet.
        if result.get("note"):
            show_warning(result.get("note"))
        return

    # Fallback
    show_json(result)


def show_pki_result(result: dict):
    """Affichage adaptatif selon le type de réponse PKI."""
    status = result.get("status", "?")
    if status == "error":
        show_error(result.get("message", "Erreur PKI"))
        return

    # Émission de certificat : retourne certificate + private_key (SENSIBLE, one-shot)
    if "private_key" in result and "certificate" in result:
        show_success(f"Certificat émis — CN : {result.get('common_name', '?')}")
        table = Table(show_header=False)
        table.add_column("Champ", style="cyan bold", min_width=18)
        table.add_column("Valeur")
        table.add_row("Serial",     result.get("serial_number", "?"))
        table.add_row("Expiration", str(result.get("expiration", "?")))
        if result.get("s3_sync_ok") is False:
            table.add_row("[red]S3 sync[/red]", "[red]ÉCHEC[/red]")
        console.print(table)
        console.print("\n[bold yellow]⚠️  CLÉ PRIVÉE — affichée une seule fois, à sauvegarder MAINTENANT :[/bold yellow]")
        console.print(result.get("private_key", ""))
        console.print("\n[bold]Certificat :[/bold]")
        console.print(result.get("certificate", ""))
        if result.get("ca_chain"):
            console.print("\n[bold]Chaîne CA :[/bold]")
            console.print(result.get("ca_chain"))
        return

    # Setup : retourne root_mount + acme_directory
    if "root_mount" in result and "acme_directory" in result:
        lab = result.get("lab_mode", True)
        show_success(f"PKI initialisée — mode {'lab' if lab else 'prod'}")
        table = Table(show_header=False)
        table.add_column("Champ", style="cyan bold", min_width=25)
        table.add_column("Valeur")
        table.add_row("CA Racine",       result.get("root_mount", "?"))
        table.add_row("CA Intermédiaire", result.get("int_mount", "?"))
        table.add_row("ACME Directory",  result.get("acme_directory", "?"))
        table.add_row("CA Root URL",     result.get("root_pem_url", "?"))
        table.add_row("CRL URL",         result.get("crl_url", "?"))
        table.add_row("Expiration root", result.get("root_expires", "?"))
        table.add_row("SHA-256 root",    result.get("root_fingerprint_sha256", "?")[:64] + "…" if len(result.get("root_fingerprint_sha256", "")) > 64 else result.get("root_fingerprint_sha256", "?"))
        table.add_row("Domaines ACME",   ", ".join(result.get("allowed_domains", [])))
        table.add_row("TTL feuille",     result.get("leaf_ttl", "?"))
        table.add_row("EAB requis",      str(result.get("eab_required", False)))
        if result.get("eab_policy"):
            table.add_row("EAB policy",   result.get("eab_policy"))
        if result.get("s3_sync_ok") is False:
            table.add_row("[red]S3 sync[/red]", "[red]ÉCHEC — durabilité compromise[/red]")
        console.print(table)
        return

    # CA Root PEM : retourne pem + sha256_fingerprint
    if "pem" in result and "sha256_fingerprint" in result:
        show_success(f"CA Racine — expire {result.get('expires', '?')}")
        console.print(f"  [cyan]SHA-256[/cyan] : {result.get('sha256_fingerprint', '?')}")
        console.print(f"  [cyan]URL[/cyan]    : {result.get('url', '?')}")
        if result.get("usage"):
            console.print(f"  [dim]💡 {result['usage']}[/dim]")
        pem = result["pem"]
        console.print(Panel(
            pem[:300] + "\n…(tronqué)" if len(pem) > 300 else pem,
            title="CA Root PEM", border_style="cyan",
        ))
        return

    # Inventaire certs
    if "certs" in result and "total" in result:
        total = result.get("total", 0)
        console.print(f"\n[bold]{total} certificat(s) émis[/bold]")
        certs = result.get("certs", [])
        if not certs:
            console.print("  [dim](aucun certificat)[/dim]")
            return
        table = Table(show_header=True)
        table.add_column("Série", style="cyan", min_width=20)
        table.add_column("SANs")
        table.add_column("Expiration")
        table.add_column("Statut", min_width=8)
        for c in certs:
            sans = ", ".join(c.get("sans", [])) or "—"
            exp  = c.get("not_after", "?")[:19].replace("T", " ") if c.get("not_after") else "?"
            rev  = "[red]révoqué[/red]" if c.get("revoked") else "[green]actif[/green]"
            table.add_row(c.get("serial", "?"), sans, exp, rev)
        console.print(table)
        return

    # Révocation
    if "serial_number" in result and "crl_updated" in result:
        show_success(f"Certificat révoqué : {result['serial_number']}")
        console.print(f"  CRL mise à jour : {result.get('crl_updated', False)}")
        if result.get("s3_sync_ok") is False:
            show_warning("S3 sync échouée — CRL peut être obsolète en S3")
        return

    # Rotation intermédiaire
    if "new_issuer_id" in result:
        show_success("Rotation intermédiaire effectuée")
        table = Table(show_header=False)
        table.add_column("Champ", style="cyan bold", min_width=22)
        table.add_column("Valeur")
        table.add_row("Ancien issuer", result.get("old_issuer_id", "?"))
        table.add_row("Nouvel issuer", result.get("new_issuer_id", "?"))
        table.add_row("Expiration",    result.get("new_expires", "?"))
        table.add_row("Ancien gardé",  str(result.get("keep_old_issuer", True)))
        if result.get("s3_sync_ok") is False:
            table.add_row("[red]S3 sync[/red]", "[red]ÉCHEC[/red]")
        console.print(table)
        return

    # Liste rôles
    if "roles" in result and "count" in result:
        n = result.get("count", 0)
        console.print(f"\n[bold]{n} rôle(s) PKI[/bold]")
        for r in result.get("roles", []):
            console.print(f"  🔐 {r}")
        return

    # Détails rôle
    if "role_name" in result and "allowed_domains" in result:
        console.print(f"\n[bold]Rôle PKI : {result['role_name']}[/bold]")
        table = Table(show_header=True)
        table.add_column("Paramètre", style="cyan bold", min_width=28)
        table.add_column("Valeur")
        table.add_row("allowed_domains",           ", ".join(result.get("allowed_domains", [])))
        table.add_row("allow_subdomains",          str(result.get("allow_subdomains", False)))
        table.add_row("allow_wildcard_certificates", str(result.get("allow_wildcard_certificates", False)))
        table.add_row("server_flag",               str(result.get("server_flag", False)))
        table.add_row("client_flag",               str(result.get("client_flag", False)))
        table.add_row("allow_ip_sans",             str(result.get("allow_ip_sans", False)))
        table.add_row("allow_localhost",           str(result.get("allow_localhost", False)))
        table.add_row("max_ttl",                   str(result.get("max_ttl", "")))
        table.add_row("key_type",                  str(result.get("key_type", "")))
        table.add_row("key_bits",                  str(result.get("key_bits", "")))
        console.print(table)
        return

    show_json(result)


def show_mission_binding_result(result: dict):
    """Affichage des résultats mission-binding (#69) : create/get/list/delete/purge."""
    status = result.get("status", "?")

    if status == "error":
        show_error(result.get("message", "Erreur"))
        return

    # --- LIST ---
    bindings = result.get("bindings")
    if bindings is not None:
        console.print(f"\n✅ [bold]{len(bindings)} binding(s) mission[/bold]")
        if bindings:
            table = Table(show_header=True)
            table.add_column("Tenant", style="cyan bold", min_width=12)
            table.add_column("Coffres", style="white")
            table.add_column("Permissions", style="green")
            table.add_column("Policy", style="yellow")
            table.add_column("Statut")
            for b in bindings:
                vaults = ", ".join(b.get("allowed_resources", []))
                perms = ", ".join(b.get("permissions", []))
                policy = b.get("policy_id", "") or ""
                if not b.get("enabled", False):
                    st = "[red]désactivé[/red]"
                elif b.get("expired"):
                    st = "[yellow]expiré[/yellow]"
                else:
                    exp = b.get("expires_at") or "jamais"
                    st = f"[green]actif[/green] → {exp[:10] if exp != 'jamais' else exp}"
                table.add_row(b.get("tenant_id", "?"), vaults, perms, policy, st)
            console.print(table)
        return

    # --- PURGE (dry-run ou réel) ---
    if "purged" in result or "candidates" in result:
        n = result.get("count", 0)
        retention = result.get("older_than_days", "?")
        if result.get("dry_run"):
            console.print(f"\n🔎 [bold]{n} binding(s) expiré(s)[/bold] seraient purgés (rétention {retention} j)")
        else:
            console.print(f"\n🗑️  [bold]{n} binding(s) expiré(s) purgé(s)[/bold]")
        return

    # --- DELETE ---
    if status == "deleted":
        console.print(f"\n✅ Binding du tenant '[cyan]{result.get('tenant_id', '?')}[/cyan]' supprimé.")
        return

    # --- CREATE / GET (détail d'un binding) ---
    if result.get("tenant_id"):
        title = "Binding créé" if status == "created" else "Binding"
        console.print(f"\n✅ [bold]{title} — tenant '{result.get('tenant_id')}'[/bold]")
        console.print(f"  Coffres     : [cyan]{', '.join(result.get('allowed_resources', []))}[/cyan]")
        console.print(f"  Permissions : [green]{', '.join(result.get('permissions', []))}[/green]")
        console.print(f"  Policy      : [yellow]{result.get('policy_id', '') or '(aucune)'}[/yellow]")
        console.print(f"  Activé      : {result.get('enabled', True)}")
        console.print(f"  Expire      : {result.get('expires_at') or 'jamais'}")
        return

    show_json(result)
