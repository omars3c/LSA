from __future__ import annotations

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from LSA.session import AwsContext


def audit_s3(ctx: AwsContext, *, console: Console) -> None:
    s3 = ctx.session.client("s3")

    table = Table(title="S3 Bucket Audit (Public Exposure)", show_lines=False)
    table.add_column("Bucket", style="white")
    table.add_column("Status", style="white", no_wrap=True)
    table.add_column("Risk", style="white", no_wrap=True)

    buckets = s3.list_buckets().get("Buckets", [])
    if not buckets:
        console.print("[green]S3: no buckets found.[/]\n")
        return

    for b in buckets:
        name = b.get("Name", "<unknown>")
        is_public = False
        risk = "Low"

        # 1) Public Access Block signals (heuristic)
        try:
            pab = s3.get_public_access_block(Bucket=name).get("PublicAccessBlockConfiguration", {}) or {}
            # Requirement: if IgnorePublicAcls or BlockPublicPolicy are False => risk
            if pab.get("IgnorePublicAcls") is False or pab.get("BlockPublicPolicy") is False:
                is_public = True
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in {"AccessDenied", "AccessDeniedException"}:
                console.print(f"[yellow]Warning[/]: AccessDenied reading PublicAccessBlock for bucket '{name}'. Skipping this check.")
            elif code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
                # No PAB config is a risk signal; keep Low unless ACL proves public.
                is_public = True
            else:
                raise

        # 2) ACL check (critical if AllUsers present)
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []) or []:
                grantee = grant.get("Grantee", {}) or {}
                uri = grantee.get("URI")
                if uri == "http://acs.amazonaws.com/groups/global/AllUsers":
                    is_public = True
                    risk = "High"
                    break
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "")
            if code in {"AccessDenied", "AccessDeniedException"}:
                console.print(f"[yellow]Warning[/]: AccessDenied reading ACL for bucket '{name}'. Skipping this check.")
            else:
                raise

        status = "Public" if is_public else "Private"
        status_style = "bold red" if is_public else "green"
        risk_style = "bold red" if risk == "High" else "yellow"

        table.add_row(
            name,
            f"[{status_style}]{status}[/{status_style}]",
            f"[{risk_style}]{risk}[/{risk_style}]",
        )

    console.print(table)
    console.print()


