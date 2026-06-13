#!/usr/bin/env python3
"""
SIFT Guardian - Main CLI Interface
Autonomous forensic investigation with self-correction
"""

import asyncio
import sys
import logging
from pathlib import Path
from typing import Optional

import click
import yaml
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

# Add src to path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from src.agent import Investigator


console = Console()


def load_config(config_path: str = "config/config.yaml") -> dict:
    """Load configuration"""
    try:
        with open(config_path, "r") as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        console.print(f"[red]Error: Config file not found: {config_path}[/red]")
        console.print("[yellow]Run: python setup.py --configure[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Error loading config: {e}[/red]")
        sys.exit(1)


def setup_logging(verbose: bool = False):
    """Setup logging"""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler("sift_guardian.log"),
            logging.StreamHandler() if verbose else logging.NullHandler(),
        ]
    )


@click.group()
@click.version_option(version="1.0.0")
def cli():
    """
    🛡️ SIFT Guardian - Autonomous Forensic Investigation Agent
    
    Self-correcting AI agent for digital forensics and incident response.
    """
    pass


@cli.command()
@click.argument("evidence_path", type=click.Path(exists=True))
@click.option("--config", default="config/config.yaml", help="Config file path")
@click.option("--provider", help="AI provider (gemini, groq, claude, ollama)")
@click.option("--case-id", help="Custom case ID")
@click.option("--verbose", "-v", is_flag=True, help="Verbose output")
@click.option("--report-format", default="markdown", help="Report format")
def investigate(
    evidence_path: str,
    config: str,
    provider: Optional[str],
    case_id: Optional[str],
    verbose: bool,
    report_format: str
):
    """
    Run autonomous investigation on evidence
    
    Example:
        python investigate.py evidence/sample.dd
        python investigate.py --provider groq evidence/memory.raw
    """
    setup_logging(verbose)
    
    # Load config
    cfg = load_config(config)
    
    # Override provider if specified
    if provider:
        cfg["ai"]["provider"] = provider
    
    # Show header
    console.print("\n[bold cyan]🛡️  SIFT Guardian - Autonomous Investigation[/bold cyan]")
    console.print(f"[dim]Evidence: {evidence_path}[/dim]")
    console.print(f"[dim]AI Provider: {cfg['ai']['provider']}[/dim]")
    console.print(f"[dim]Case ID: {case_id or 'auto-generated'}[/dim]\n")
    
    # Run investigation
    asyncio.run(_run_investigation(cfg, evidence_path, case_id, report_format))


async def _run_investigation(
    config: dict,
    evidence_path: str,
    case_id: Optional[str],
    report_format: str
):
    """Run the investigation"""
    
    try:
        # Initialize investigator
        with console.status("[bold green]Initializing investigator..."):
            investigator = Investigator(config, case_id)
        
        console.print("[green]✓[/green] Investigator initialized\n")
        
        # Run investigation with progress
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            
            task = progress.add_task(
                "[cyan]Investigating... (this may take several minutes)",
                total=None
            )
            
            result = await investigator.investigate(evidence_path)
            
            progress.update(task, completed=True)
        
        # Display results
        _display_results(result)
        
        # Save report
        _save_report(result, report_format)
        
    except KeyboardInterrupt:
        console.print("\n[yellow]Investigation interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[red]✗ Investigation failed: {e}[/red]")
        if "--verbose" in sys.argv or "-v" in sys.argv:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


def _display_results(result: dict):
    """Display investigation results"""
    
    console.print("\n[bold]📊 Investigation Results[/bold]\n")
    
    # Summary
    console.print(f"[bold]Case ID:[/bold] {result['case_id']}")
    console.print(f"[bold]Status:[/bold] {result['status']}")
    console.print(f"[bold]Duration:[/bold] {result['duration_seconds']:.1f} seconds")
    console.print(f"[bold]Findings:[/bold] {len(result['findings'])}\n")
    
    # Findings table
    if result["findings"]:
        table = Table(title="Findings", show_header=True, header_style="bold magenta")
        table.add_column("ID", style="cyan", width=12)
        table.add_column("Severity", style="yellow", width=10)
        table.add_column("Confidence", style="green", width=10)
        table.add_column("Description", width=50)
        table.add_column("Corrected", width=10)
        
        for finding in result["findings"]:
            # Color-code severity
            severity_colors = {
                "critical": "red",
                "high": "orange1",
                "medium": "yellow",
                "low": "green",
                "info": "blue",
            }
            severity_color = severity_colors.get(finding["severity"], "white")
            
            # Truncate description
            desc = finding["description"]
            if len(desc) > 50:
                desc = desc[:47] + "..."
            
            # Corrected indicator
            corrected_mark = "✓" if finding.get("corrected") else ""
            
            table.add_row(
                finding["id"],
                f"[{severity_color}]{finding['severity'].upper()}[/{severity_color}]",
                f"{finding['confidence']:.2f}",
                desc,
                corrected_mark
            )
        
        console.print(table)
    else:
        console.print("[yellow]No findings generated[/yellow]")
    
    console.print()


def _save_report(result: dict, format: str):
    """Save investigation report"""
    
    # Create reports directory
    reports_dir = Path("./reports")
    reports_dir.mkdir(exist_ok=True)
    
    # Generate filename
    case_id = result["case_id"]
    report_file = reports_dir / f"{case_id}_report.{format}"
    
    # Save report
    try:
        with open(report_file, "w", encoding="utf-8") as f:
            if format == "markdown":
                f.write(f"# Investigation Report - {case_id}\n\n")
                f.write(result["report"])
                f.write("\n\n## Findings\n\n")
                for finding in result["findings"]:
                    f.write(f"### {finding['id']}\n")
                    f.write(f"- **Description**: {finding['description']}\n")
                    f.write(f"- **Confidence**: {finding['confidence']}\n")
                    f.write(f"- **Severity**: {finding['severity']}\n")
                    if finding.get("corrected"):
                        f.write(f"- **Corrected**: Yes (reason: {finding.get('correction_reason')})\n")
                    f.write("\n")
            elif format == "json":
                import json
                json.dump(result, f, indent=2)
        
        console.print(f"[green]✓[/green] Report saved to: [cyan]{report_file}[/cyan]")
        
    except Exception as e:
        console.print(f"[yellow]Warning: Could not save report: {e}[/yellow]")


@cli.command()
@click.option("--config", default="config/config.yaml", help="Config file")
def status(config: str):
    """Check system status and configuration"""
    
    console.print("[bold]🏥 SIFT Guardian Status[/bold]\n")
    
    # Load config
    try:
        cfg = load_config(config)
        console.print("[green]✓[/green] Configuration loaded")
    except:
        console.print("[red]✗[/red] Configuration error")
        return
    
    # Check AI provider
    try:
        from src.ai import get_provider
        provider = get_provider(cfg)
        if provider.is_available():
            console.print(f"[green]✓[/green] AI Provider ({cfg['ai']['provider']}) available")
        else:
            console.print(f"[yellow]⚠[/yellow] AI Provider ({cfg['ai']['provider']}) not configured")
    except Exception as e:
        console.print(f"[red]✗[/red] AI Provider error: {e}")
    
    # Check directories
    for dir_name in ["audit_logs", "reports", "evidence"]:
        dir_path = Path(dir_name)
        if dir_path.exists():
            console.print(f"[green]✓[/green] Directory {dir_name}/ exists")
        else:
            console.print(f"[yellow]⚠[/yellow] Directory {dir_name}/ not found")
    
    console.print("\n[bold]Configuration:[/bold]")
    console.print(f"  AI Provider: {cfg['ai']['provider']}")
    console.print(f"  Model: {cfg['ai']['model']}")
    console.print(f"  Self-Correction: {cfg['self_correction']['enabled']}")
    console.print(f"  Security Guardrails: {cfg['security']['command_whitelist_enabled']}")
    console.print(f"  Audit Logging: {cfg['audit']['enabled']}")


@cli.command()
def version():
    """Show version information"""
    console.print("[bold]🛡️ SIFT Guardian[/bold]")
    console.print("Version: 1.0.0")
    console.print("For SANS Find Evil! Hackathon 2026")


if __name__ == "__main__":
    cli()
