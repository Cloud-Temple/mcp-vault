# -*- coding: utf-8 -*-
"""
Fonctions d'affichage Rich — MCP Vault.message:%3CTu40nr-QR5qWTsOCzcBI3w@geopod-ismtpd-5%3E
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
            table.add_column("Space ID", style="cyan bold", min_width=20)
            table.add_column("Description", style="dim")
            table.add_column("Secrets", style="green", justify="right")
            for s in vaults:
                table.add_row(
                    s.get("vault_id", "?"),
                    s.get("description", ""),
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

    # CA Setup
    if "ca_public_key" in result and "role" in result:
        show_success(f"SSH CA configurée (rôle: {result.get('role', '?')})")
        console.print(Panel(
            result.get("ca_public_key", "?"),
            title="Clé publique CA (à mettre dans TrustedUserCAKeys)",
            border_style="cyan",
        ))
        return

    # Sign key
    signed = result.get("signed_key")
    if signed:
        show_success(f"Clé signée (TTL: {result.get('ttl', '?')})")
        console.print(Panel(
            signed[:200] + "..." if len(signed) > 200 else signed,
            title="Certificat SSH",
            border_style="green",
        ))
        return

    # CA public key
    pub_key = result.get("ca_public_key") or result.get("public_key")
    if pub_key:
        console.print(Panel(pub_key, title="Clé publique CA", border_style="cyan"))
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
            console.print(f"  Spaces      : [cyan]{', '.join(resources)}[/cyan]")
        else:
            console.print(f"  Spaces      : [dim](tous)[/dim]")
        console.print(f"  Expire      : {result.get('expires_at') or 'jamais'}")
        return

    # --- LIST ---
    tokens = result.get("tokens")
    if tokens is not None:
        console.print(f"\n✅ [bold]{len(tokens)} token(s)[/bold]")
        if tokens:
            table = Table(show_header=True)
            table.add_column("Client", style="cyan bold", min_width=15)
            table.add_column("Email", style="dim")
            table.add_column("Permissions", style="green")
            table.add_column("Spaces", style="white")
            table.add_column("Expire", style="dim")
            table.add_column("Hash", style="dim")
            for t in tokens:
                allowed_vaults = ", ".join(t.get("allowed_resources", [])) or "(tous)"
                exp = t.get("expires_at") or "jamais"
                if t.get("revoked"):
                    exp = f"[red]RÉVOQUÉ[/red]"
                elif exp != "jamais":
                    exp = exp[:10]
                table.add_row(
                    t.get("client_name", "?"),
                    t.get("email", "") or "",
                    ", ".join(t.get("permissions", [])),
                    allowed_vaults,
                    exp,
                    t.get("hash_prefix", "?"),
                )
            console.print(table)
        return

    # --- REVOKE ---
    if result.get("message"):
        show_success(result["message"])
        return

    show_json(result)
