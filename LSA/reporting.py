from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from rich.console import Console
from rich.table import Table


@dataclass(frozen=True)
class Finding:
    service: str
    check: str
    severity: str  # INFO | LOW | MEDIUM | HIGH
    resource: str
    message: str
    recommendation: Optional[str] = None


def make_findings_table(findings: list[Finding]) -> Table:
    table = Table(title="Findings", show_lines=False)
    table.add_column("Service", style="cyan", no_wrap=True)
    table.add_column("Check", style="white")
    table.add_column("Severity", style="bold")
    table.add_column("Resource", style="magenta")
    table.add_column("Message", style="white")

    def sev_style(sev: str) -> str:
        sev = sev.upper()
        if sev == "HIGH":
            return "bold red"
        if sev == "MEDIUM":
            return "bold yellow"
        if sev == "LOW":
            return "green"
        return "dim"

    for f in findings:
        table.add_row(
            f.service,
            f.check,
            f"[{sev_style(f.severity)}]{f.severity.upper()}[/]",
            f.resource,
            f.message,
        )

    return table


def print_summary(console: Console, findings: list[Finding]) -> None:
    by_sev = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        s = f.severity.upper()
        by_sev[s] = by_sev.get(s, 0) + 1

    summary = Table(title="Summary", show_header=True, header_style="bold")
    summary.add_column("HIGH", justify="right", style="bold red")
    summary.add_column("MEDIUM", justify="right", style="bold yellow")
    summary.add_column("LOW", justify="right", style="green")
    summary.add_column("INFO", justify="right", style="dim")
    summary.add_row(str(by_sev.get("HIGH", 0)), str(by_sev.get("MEDIUM", 0)), str(by_sev.get("LOW", 0)), str(by_sev.get("INFO", 0)))
    console.print(summary)


