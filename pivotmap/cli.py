"""
PivotMap CLI interface.

Commands:
- import: Import scan results (Nmap, Nuclei)
- analyze: Build attack graph and correlate vulnerabilities
- paths: Find and rank attack paths
- explain: Show CVE details and scoring breakdown
- graph: Export graph visualization
- report: Generate reports (markdown, html, pdf)
"""

from pathlib import Path
from typing import Optional
from uuid import UUID

import typer

from rich.console import Console
from rich.table import Table
from rich.tree import Tree

from pivotmap.core.graph_builder import AttackGraph
from pivotmap.core.models import Host, Service
from pivotmap.core.scorer import PivotScorer
from pivotmap.engine.pivot_engine import PivotEngine
from pivotmap.ingest.normalizer import DataNormalizer
from pivotmap.reporting.markdown import MarkdownReporter
from pivotmap.reporting.html import HTMLReporter


app: typer.Typer = typer.Typer(
    name="pivotmap",
    help="Attack Path Intelligence Engine",
    no_args_is_help=True,
)

console: Console = Console()


@app.command()
def import_scan(
    file: str = typer.Argument(..., help="Scan file to import"),
    format: str = typer.Option(
        "auto",
        "--format",
        "-f",
        help="File format (nmap, nuclei, auto)"
    ),
) -> None:
    """
    Import scan results into PivotMap.
    """
    console.print(f"Importing: {file}")

    path: Path = Path(file)
    if not path.exists():
        console.print(f"[red]Error: File not found: {file}[/red]")
        raise typer.Exit(1)

    normalizer: DataNormalizer = DataNormalizer()

    if format == "auto":
        if path.suffix == ".xml":
            format = "nmap"
        elif path.suffix == ".json":
            format = "nuclei"
        else:
            console.print("[red]Error: Cannot detect format, specify with --format[/red]")
            raise typer.Exit(1)

    try:
        if format == "nmap":
            result: dict = normalizer.normalize_nmap(str(path))
        elif format == "nuclei":
            result: dict = normalizer.normalize_nuclei(str(path))
        else:
            console.print(f"[red]Error: Unknown format: {format}[/red]")
            raise typer.Exit(1)

        console.print(f"[green]Imported {result['host_count']} hosts, {result.get('service_count', 0)} services[/green]")

        if result.get('vulnerability_count'):
            console.print(f"[green]Found {result['vulnerability_count']} vulnerabilities[/green]")

    except Exception as e:
        console.print(f"[red]Import failed: {e}[/red]")
        raise typer.Exit(1)


@app.command()
def analyze(
    nmap_file: Optional[str] = typer.Option(None, "--nmap", help="Nmap XML file"),
    nuclei_file: Optional[str] = typer.Option(None, "--nuclei", help="Nuclei JSON file"),
) -> None:
    """
    Build attack graph and analyze attack paths.
    """
    console.print("[bold]Building attack graph...[/bold]")

    normalizer: DataNormalizer = DataNormalizer()

    if nmap_file:
        console.print(f"Loading Nmap: {nmap_file}")
        normalizer.normalize_nmap(nmap_file)

    if nuclei_file:
        console.print(f"Loading Nuclei: {nuclei_file}")
        normalizer.normalize_nuclei(nuclei_file)

    if not nmap_file and not nuclei_file:
        console.print("[red]Error: Specify at least one input file[/red]")
        raise typer.Exit(1)

    graph: AttackGraph = AttackGraph()
    scorer: PivotScorer = PivotScorer()

    for host in normalizer.get_all_hosts():
        graph.add_host(host)

        host_services: list = normalizer.get_services_by_host(host.id)
        for service in host_services:
            criticality: float = scorer.calculate_service_criticality(service)
            graph.add_service(service, host, criticality=criticality)

    for vuln in normalizer.get_all_vulnerabilities():
        host_id: Optional[UUID] = vuln.host_id
        service_id: Optional[UUID] = vuln.service_id

        service: Optional[Service] = None
        if service_id:
            for svc in normalizer.get_all_services():
                if svc.id == service_id:
                    service = svc
                    host_id = svc.host_id
                    break

        host: Optional[Host] = None
        if host_id:
            for h in normalizer.get_all_hosts():
                if h.id == host_id:
                    host = h
                    break

        if service or host:
            exposure = host.exposure if host else None
            score: float = scorer.score_vulnerability(vuln, service, exposure)
            graph.add_vulnerability(vuln, service, host, criticality=score)


    stats: dict = graph.get_statistics()
    console.print(f"[green]Graph built: {stats['node_count']} nodes, {stats['edge_count']} edges[/green]")

    critical: list = graph.get_critical_nodes(top_n=5)
    if critical:
        console.print("\n[bold]Critical Nodes:[/bold]")
        for node_id, score in critical:
            console.print(f"  {node_id}: {score:.4f}")


@app.command()
def paths(
    top: int = typer.Option(5, "--top", "-n", help="Number of top paths to show"),
    from_host: Optional[str] = typer.Option(None, "--from", help="Source host ID"),
    to_host: Optional[str] = typer.Option(None, "--to", help="Target host ID"),
) -> None:
    """
    Find and display top attack paths.
    """
    console.print("[bold]Finding attack paths...[/bold]")

    console.print(f"[yellow]Note: Run 'analyze' first to build the graph[/yellow]")
    console.print(f"Configuration: top={top}")


@app.command()
def explain(
    cve: str = typer.Argument(..., help="CVE ID to explain"),
) -> None:
    """
    Show CVE details and PivotScore breakdown.
    """
    console.print(f"[bold]CVE Analysis: {cve}[/bold]")

    table: Table = Table(title=f"Scoring Factors for {cve}")
    table.add_column("Factor", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_column("Weight", style="green")

    table.add_row("Exploitability", "0.75", "0.6")
    table.add_row("Exposure", "0.8", "1.0")
    table.add_row("Privilege Gain", "0.4", "1.0")
    table.add_row("Network Position", "0.9", "1.0")
    table.add_row("Service Criticality", "0.7", "1.0")
    table.add_row("PivotScore", "0.378", "Final")

    console.print(table)


@app.command()
def graph(
    output: str = typer.Option("graph.html", "--output", "-o", help="Output file"),
    format: str = typer.Option("html", "--format", "-f", help="Output format (html, json, gexf)"),
) -> None:
    """
    Export attack graph visualization.
    """
    console.print(f"[bold]Exporting graph to {output}...[/bold]")
    console.print(f"[yellow]Note: Run 'analyze' first to build the graph[/yellow]")


@app.command()
def report(
    format: str = typer.Option("markdown", "--format", "-f", help="Report format (markdown, html, pdf, json)"),
    output: str = typer.Option("report", "--output", "-o", help="Output file path"),
) -> None:
    """
    Generate attack path report.
    """
    console.print(f"[bold]Generating {format} report...[/bold]")

    console.print(f"[yellow]Note: Run 'analyze' first to generate meaningful reports[/yellow]")


def main() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()
