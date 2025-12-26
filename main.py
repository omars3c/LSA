from __future__ import annotations

import argparse
import sys

from botocore.exceptions import ClientError, NoCredentialsError
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from checks.ec2_security_groups import audit_security_groups
from checks.iam_entry import audit_iam
from checks.s3_entry import audit_s3
from LSA.session import build_aws_context


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="LCA (Lightweight Cloud Auditor)")
    p.add_argument(
        "--service",
        choices=["ec2", "s3", "iam", "all"],
        default="all",
        help="Which service to audit (default: all)",
    )
    p.add_argument("--region", default="us-east-1", help="AWS region (default: us-east-1)")
    return p.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    args = parse_args(argv)

    console = Console()

    title = Text("LCA (Lightweight Cloud Auditor)", style="bold cyan")
    subtitle = Text("AWS Security Compliance (MVP)", style="dim")
    created_by = Text("Created by: Omar Alikhanov  Linkedin: https://www.linkedin.com/in/omars3c/", style="dim")
    console.print(Panel.fit(Text.assemble(title, "\n", subtitle, "\n", created_by), border_style="cyan"))

    ctx = build_aws_context(profile=None, region=args.region)
    acct = ctx.account_id or "unknown"
    reg = ctx.region or "not set"
    console.print(f"[bold]Account[/]: {acct}    [bold]Region[/]: {reg}\n")

    try:
        if args.service in {"ec2", "all"}:
            with console.status("Running EC2 checks..."):
                audit_security_groups(ctx, console=console)

        if args.service in {"s3", "all"}:
            with console.status("Running S3 checks..."):
                audit_s3(ctx, console=console)

        if args.service in {"iam", "all"}:
            with console.status("Running IAM checks..."):
                audit_iam(ctx, console=console)

        return 0

    except NoCredentialsError:
        console.print(
            "[bold red]AWS credentials not found.[/]\n"
            "[red]Please configure AWS CLI: run `aws configure` or set environment variables "
            "AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY (+ AWS_SESSION_TOKEN if needed).[/]"
        )
        return 2
    except ClientError as e:
        console.print(
            "[bold red]AWS API error (нет прав или неверная конфигурация).[/]\n"
            f"[red]{e}[/]\n"
            "[red]Please configure AWS CLI and permissions (IAM policies/roles) to run the audit.[/]"
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())


