from __future__ import annotations

from rich.console import Console
from rich.table import Table

from LSA.reporting import Finding
from LSA.session import AwsContext


def audit_security_groups(ctx: AwsContext, *, console: Console | None = None) -> list[Finding]:
    """
    Admin-friendly EC2 Security Groups audit:
    - iterate all security groups
    - find ingress rules where CidrIp == 0.0.0.0/0
    - highlight critical ports (22/3389/3306/5432)
    - print a table: SG ID, open port/range, risk warning
    """
    if not ctx.region:
        f = Finding(
            service="EC2",
            check="RegionResolved",
            severity="HIGH",
            resource="*",
            message="No region could be resolved. Provide --region or set AWS_REGION/AWS_DEFAULT_REGION.",
        )
        if console:
            console.print(f"[bold red]EC2[/] {f.message}")
        return [f]

    ec2 = ctx.session.client("ec2", region_name=ctx.region)
    findings: list[Finding] = []

    table: Table | None = None
    if console:
        table = Table(title=f"EC2 Security Groups (Ingress open to 0.0.0.0/0) - {ctx.region}", show_lines=False)
        table.add_column("GroupId", style="cyan", no_wrap=True)
        table.add_column("Port", style="white", no_wrap=True)
        table.add_column("Protocol", style="white", no_wrap=True)
        table.add_column("Risk", style="white")

    rows = 0
    paginator = ec2.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page.get("SecurityGroups", []):
            sg_id = sg.get("GroupId", "<unknown>")
            for perm in sg.get("IpPermissions", []):
                ip_ranges = perm.get("IpRanges", [])
                if not any((r.get("CidrIp") == "0.0.0.0/0") for r in ip_ranges):
                    continue

                ip_proto = perm.get("IpProtocol", "")
                from_p = perm.get("FromPort")
                to_p = perm.get("ToPort")

                proto_label = "all" if ip_proto == "-1" else (ip_proto or "unknown")

                # Port formatting and risk classification
                port_label = "ALL" if ip_proto == "-1" else _format_port_range(from_p, to_p)
                crit = _is_critical_exposure(from_p, to_p, ip_proto)

                risk_text = (
                    "CRITICAL: exposed management/database port to the Internet"
                    if crit
                    else "Open to the Internet (review necessity)"
                )
                risk_style = "bold red" if crit or ip_proto == "-1" else "yellow"

                if table is not None:
                    table.add_row(
                        sg_id,
                        f"[{risk_style}]{port_label}[/{risk_style}]",
                        proto_label,
                        f"[{risk_style}]{risk_text}[/{risk_style}]",
                    )
                    rows += 1

                findings.append(
                    Finding(
                        service="EC2",
                        check="SecurityGroupIngressWorld",
                        severity="HIGH" if (crit or ip_proto == "-1") else "MEDIUM",
                        resource=sg_id,
                        message=f"Ingress open to 0.0.0.0/0 on {proto_label} {port_label}. {risk_text}",
                        recommendation="Restrict source CIDRs, use VPN/SSM/bastion, and remove public exposure where possible.",
                    )
                )

    if console and table is not None:
        if rows == 0:
            console.print("[green]EC2: no ingress rules open to 0.0.0.0/0 found (IPv4).[/]\n")
        else:
            console.print(table)
            console.print()

    if not findings:
        findings.append(
            Finding(
                service="EC2",
                check="SecurityGroupIngressWorld",
                severity="INFO",
                resource="*",
                message="No ingress rules open to 0.0.0.0/0 found (IPv4).",
            )
        )

    return findings


def _format_port_range(from_p, to_p) -> str:
    if from_p is None or to_p is None:
        return "N/A"
    if from_p == to_p:
        return str(from_p)
    return f"{from_p}-{to_p}"


def _is_critical_exposure(from_p, to_p, ip_proto: str | None) -> bool:
    if ip_proto == "-1":
        return True
    if from_p is None or to_p is None:
        return False
    for p in (22, 3389, 3306, 5432):
        if from_p <= p <= to_p:
            return True
    return False


