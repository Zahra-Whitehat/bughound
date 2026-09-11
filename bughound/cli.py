"""Command-line interface for bughound."""

from __future__ import annotations

import asyncio
import os
import sys
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table

from .authorization import AuthorizationError, load_scope
from .engine import run_scan
from .models import ScanConfig
from .modules.base import REGISTRY, load_all_modules
from .reporting import to_json, to_markdown

console = Console()


@click.group()
@click.version_option()
def main() -> None:
    """bughound: authorized web-vulnerability hunting agent."""


@main.command("list-modules")
def list_modules() -> None:
    """List available scanner modules."""

    load_all_modules()
    table = Table(title="bughound modules")
    table.add_column("Name")
    table.add_column("Mode")
    table.add_column("Categories")
    for name, cls in sorted(REGISTRY.items()):
        mode = "aggressive" if cls.aggressive_required else ("passive" if cls.passive else "active")
        cats = ", ".join(c.value for c in cls.categories)
        table.add_row(name, mode, cats)
    console.print(table)


@main.command()
@click.argument("url")
@click.option("--scope", "scope_file", type=click.Path(exists=True), help="YAML scope file.")
@click.option("--authorize-host", "authorize_hosts", multiple=True, help="Host/glob you are authorized to test.")
@click.option("--deny-host", "deny_hosts", multiple=True, help="Host/glob that is forbidden and must never be contacted (overrides scope).")
@click.option("--deny-url", "deny_urls", multiple=True, help="URL/prefix that is forbidden and must never be contacted (overrides scope).")
@click.option("--i-am-authorized", is_flag=True, help="Confirm you are authorized to test this target.")
@click.option("--aggressive/--safe", default=False, help="Enable active exploitation payloads (authorized only).")
@click.option("--max-urls", default=40, show_default=True)
@click.option("--max-depth", default=2, show_default=True)
@click.option("--timeout", default=15.0, show_default=True)
@click.option("--module", "modules", multiple=True, help="Only run these modules.")
@click.option("--no-external", is_flag=True, help="Do not run external tools (nuclei/nmap/sqlmap).")
@click.option("--out", "out_dir", default="reports", show_default=True, help="Output directory.")
@click.option("--header", "headers", multiple=True, help="Extra request header 'Name: value'.")
def scan(url, scope_file, authorize_hosts, deny_hosts, deny_urls, i_am_authorized, aggressive,
         max_urls, max_depth, timeout, modules, no_external, out_dir, headers) -> None:
    """Scan a URL for vulnerabilities and write reports."""

    extra_headers = {}
    for h in headers:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    scope = load_scope(
        scope_file=scope_file,
        explicit_hosts=list(authorize_hosts),
        denied_hosts=list(deny_hosts),
        denied_urls=list(deny_urls),
    )
    config = ScanConfig(
        target_url=url,
        max_urls=max_urls,
        max_depth=max_depth,
        timeout=timeout,
        aggressive=aggressive,
        modules=list(modules) or None,
        extra_headers=extra_headers,
        use_external_tools=not no_external,
    )

    console.print(f"[bold]bughound[/bold] scanning [cyan]{url}[/cyan] "
                  f"({'aggressive' if aggressive else 'safe'} mode)")

    try:
        result = asyncio.run(
            run_scan(config, scope, confirmed=i_am_authorized, progress=lambda m: console.log(m))
        )
    except AuthorizationError as exc:
        console.print(f"[bold red]Authorization error:[/bold red] {exc}")
        sys.exit(2)

    _print_summary(result)

    os.makedirs(out_dir, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    host = result.target.host or "target"
    base = os.path.join(out_dir, f"{host}-{stamp}")
    with open(base + ".json", "w") as fh:
        fh.write(to_json(result))
    with open(base + ".md", "w") as fh:
        fh.write(to_markdown(result))
    console.print(f"\n[green]Reports written:[/green] {base}.md , {base}.json")


@main.command()
@click.option("--host", default="127.0.0.1", show_default=True)
@click.option("--port", default=8000, show_default=True)
def serve(host, port) -> None:
    """Run the web service + dashboard."""

    import uvicorn

    uvicorn.run("bughound.web:app", host=host, port=port, reload=False)


def _print_summary(result) -> None:
    table = Table(title="Findings")
    table.add_column("Sev")
    table.add_column("Class")
    table.add_column("Title")
    table.add_column("URL", overflow="fold")
    table.add_column("Verified")
    for f in result.sorted_findings:
        table.add_row(
            f.severity.value.upper(), f.category.value, f.title, f.url,
            "yes" if f.verified else f.confidence,
        )
    console.print(table)
    if result.errors:
        console.print("[yellow]Notes:[/yellow]")
        for e in result.errors:
            console.print(f"  - {e}")


if __name__ == "__main__":
    main()
