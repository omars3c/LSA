from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError
from rich.console import Console
from rich.table import Table

from LSA.session import AwsContext


def audit_iam(ctx: AwsContext, *, console: Console) -> None:
    iam = ctx.session.client("iam")
    now = datetime.now(timezone.utc)

    table = Table(title="IAM Users Audit", show_lines=False)
    table.add_column("User", style="cyan")
    table.add_column("MFA Enabled", style="white")
    table.add_column("Key Age Issues", style="white")
    table.add_column("Risk", style="white", no_wrap=True)

    try:
        paginator = iam.get_paginator("list_users")
        any_users = False
        for page in paginator.paginate():
            for u in page.get("Users", []) or []:
                any_users = True
                user = u.get("UserName", "<unknown>")

                # MFA status
                mfa_enabled: bool | None = None
                mfa_cell = "[yellow]Unknown[/]"
                try:
                    devices = iam.list_mfa_devices(UserName=user).get("MFADevices", []) or []
                    mfa_enabled = bool(devices)
                    mfa_cell = "[green]Yes[/]" if mfa_enabled else "[bold red]No[/]"
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code in {"AccessDenied", "AccessDeniedException"}:
                        console.print(f"[yellow]Warning[/]: AccessDenied listing MFA devices for user '{user}'.")
                        mfa_cell = "[yellow]Unknown (AccessDenied)[/]"
                        mfa_enabled = None
                    else:
                        raise

                # Access key age issue (> 90 days, Active)
                key_cell = "[green]None[/]"
                has_old_active_keys = False
                try:
                    keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", []) or []
                    old_active = 0
                    for k in keys:
                        if k.get("Status") != "Active":
                            continue
                        created = k.get("CreateDate")
                        if not created:
                            continue
                        age_days = int((now - created).total_seconds() // 86400)
                        if age_days > 90:
                            old_active += 1
                    if old_active:
                        has_old_active_keys = True
                        key_cell = f"[bold yellow]{old_active} active key(s) > 90 days[/]"
                except ClientError as e:
                    code = e.response.get("Error", {}).get("Code", "")
                    if code in {"AccessDenied", "AccessDeniedException"}:
                        console.print(f"[yellow]Warning[/]: AccessDenied listing access keys for user '{user}'.")
                        key_cell = "[yellow]Unknown (AccessDenied)[/]"
                    else:
                        raise

                # Risk classification
                # Requirement: if MFA list is empty -> CRITICAL
                if mfa_enabled is False:
                    risk = "CRITICAL"
                    risk_cell = "[bold red]CRITICAL[/]"
                elif has_old_active_keys:
                    risk = "Medium"
                    risk_cell = "[bold yellow]Medium[/]"
                else:
                    risk = "OK"
                    risk_cell = "[green]OK[/]"

                table.add_row(user, mfa_cell, key_cell, risk_cell)

        if not any_users:
            console.print("[green]IAM: no users found.[/]\n")
            return

    except ClientError as e:
        # Let main.py handle the global AWS permission/config error nicely
        raise

    console.print(table)
    console.print()


