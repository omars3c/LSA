from __future__ import annotations

from datetime import datetime, timezone

from botocore.exceptions import ClientError

from LSA.reporting import Finding
from LSA.session import AwsContext
from rich.console import Console
from rich.table import Table


def run_iam_checks(ctx: AwsContext) -> list[Finding]:
    iam = ctx.session.client("iam")
    findings: list[Finding] = []

    findings.extend(_check_root_mfa(iam))
    findings.extend(_check_password_policy(iam))

    return findings


def audit_iam_users(ctx: AwsContext, *, console: Console | None = None, stale_days: int = 90) -> list[Finding]:
    """
    IAM users audit (admin-friendly):
    - users with console access but WITHOUT MFA
    - users with AdministratorAccess attached (directly or via group)
    - access keys not used for > stale_days (stale keys)

    Prints a rich table and returns findings.
    """
    iam = ctx.session.client("iam")
    findings: list[Finding] = []
    now = datetime.now(timezone.utc)

    table: Table | None = None
    if console:
        table = Table(title=f"IAM Users Audit (stale keys > {stale_days} days)", show_lines=False)
        table.add_column("User", style="cyan")
        table.add_column("Issue", style="white")
        table.add_column("Details", style="white")
        table.add_column("Severity", style="white", no_wrap=True)

    def add_row(user: str, issue: str, details: str, severity: str) -> None:
        nonlocal table
        if table is None:
            return
        sev = severity.upper()
        sev_style = "bold red" if sev == "HIGH" else ("bold yellow" if sev == "MEDIUM" else "green")
        table.add_row(user, issue, details, f"[{sev_style}]{sev}[/{sev_style}]")

    try:
        paginator = iam.get_paginator("list_users")
        any_users = False
        for page in paginator.paginate():
            for u in page.get("Users", []):
                any_users = True
                user = u.get("UserName", "<unknown>")

                # 1) Console access without MFA
                console_access, console_note, console_sev = _has_console_access(iam, user)
                if console_access is True:
                    mfa_enabled, mfa_note, mfa_sev = _user_has_mfa(iam, user)
                    if mfa_enabled is False:
                        f = Finding(
                            service="IAM",
                            check="ConsoleAccessNoMFA",
                            severity="HIGH",
                            resource=user,
                            message="User has console access but no MFA devices configured.",
                            recommendation="Enable MFA for the user or migrate to AWS Identity Center (SSO).",
                        )
                        findings.append(f)
                        add_row(user, "Console access without MFA", mfa_note, "HIGH")
                    elif mfa_enabled is None:
                        # Unknown (e.g., access denied)
                        f = Finding(
                            service="IAM",
                            check="ConsoleAccessNoMFA",
                            severity=mfa_sev,
                            resource=user,
                            message=f"Console access detected, but MFA status unknown: {mfa_note}",
                            recommendation="Ensure iam:ListMFADevices is allowed to audit MFA status.",
                        )
                        findings.append(f)
                        add_row(user, "Console access MFA status unknown", mfa_note, mfa_sev)
                elif console_access is None:
                    # Unknown console access
                    findings.append(
                        Finding(
                            service="IAM",
                            check="ConsoleAccess",
                            severity=console_sev,
                            resource=user,
                            message=f"Console access status unknown: {console_note}",
                            recommendation="Ensure iam:GetLoginProfile is allowed to audit console access.",
                        )
                    )
                    add_row(user, "Console access unknown", console_note, console_sev)

                # 2) AdministratorAccess attached
                admin_attached, admin_detail, admin_sev = _has_administrator_access(iam, user)
                if admin_attached is True:
                    findings.append(
                        Finding(
                            service="IAM",
                            check="AdministratorAccess",
                            severity="HIGH",
                            resource=user,
                            message=f"AdministratorAccess attached: {admin_detail}",
                            recommendation="Avoid full admin on users; use least privilege and prefer roles/SSO.",
                        )
                    )
                    add_row(user, "AdministratorAccess attached", admin_detail, "HIGH")
                elif admin_attached is None:
                    findings.append(
                        Finding(
                            service="IAM",
                            check="AdministratorAccess",
                            severity=admin_sev,
                            resource=user,
                            message=f"Could not fully audit AdministratorAccess attachment: {admin_detail}",
                            recommendation="Ensure iam:ListAttachedUserPolicies, iam:ListGroupsForUser, iam:ListAttachedGroupPolicies are allowed.",
                        )
                    )
                    add_row(user, "Admin access unknown", admin_detail, admin_sev)

                # 3) Stale access keys (not used > stale_days)
                stale = _find_stale_access_keys(iam, user, now=now, stale_days=stale_days)
                for key_id, days, why in stale:
                    findings.append(
                        Finding(
                            service="IAM",
                            check="StaleAccessKey",
                            severity="MEDIUM",
                            resource=f"{user}/{key_id}",
                            message=f"Access key not used for {days} days ({why}).",
                            recommendation="Deactivate/delete unused keys; rotate credentials; prefer short-lived access (roles/SSO).",
                        )
                    )
                    add_row(user, "Stale access key", f"{key_id}: {days} days ({why})", "MEDIUM")

        if not any_users:
            findings.append(
                Finding(
                    service="IAM",
                    check="UsersPresent",
                    severity="INFO",
                    resource="*",
                    message="No IAM users found.",
                )
            )
            if console:
                console.print("[green]IAM: no users found.[/]\n")

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        f = Finding(
            service="IAM",
            check="ListUsers",
            severity="HIGH",
            resource="*",
            message=f"Failed to list IAM users: {code}",
            recommendation="Ensure iam:ListUsers is allowed.",
        )
        if console:
            console.print(f"[bold red]IAM[/] {f.message}\n")
        return [f]
    except Exception as e:
        f = Finding(
            service="IAM",
            check="ListUsers",
            severity="HIGH",
            resource="*",
            message=f"Failed to query IAM (credentials/connection issue): {e}",
            recommendation="Configure AWS credentials (env vars or ~/.aws/credentials) and try again.",
        )
        if console:
            console.print(f"[bold red]IAM[/] {f.message}\n")
        return [f]

    if console and table is not None:
        if table.row_count == 0:
            console.print("[green]IAM: no user policy violations detected (based on selected checks).[/]\n")
        else:
            console.print(table)
            console.print()

    return findings


def _check_root_mfa(iam) -> list[Finding]:
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        mfa_enabled = int(summary.get("AccountMFAEnabled", 0)) == 1
        if not mfa_enabled:
            return [
                Finding(
                    service="IAM",
                    check="RootMFA",
                    severity="HIGH",
                    resource="root",
                    message="Root account MFA is not enabled.",
                    recommendation="Enable MFA for the AWS account root user and avoid using root for day-to-day work.",
                )
            ]
        return [
            Finding(
                service="IAM",
                check="RootMFA",
                severity="INFO",
                resource="root",
                message="Root account MFA is enabled.",
            )
        ]
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        return [
            Finding(
                service="IAM",
                check="RootMFA",
                severity="MEDIUM",
                resource="root",
                message=f"Failed to read account summary: {code}",
                recommendation="Ensure iam:GetAccountSummary is allowed.",
            )
        ]
    except Exception as e:
        return [
            Finding(
                service="IAM",
                check="RootMFA",
                severity="HIGH",
                resource="root",
                message=f"Failed to query IAM (credentials/connection issue): {e}",
                recommendation="Configure AWS credentials (env vars or ~/.aws/credentials) and try again.",
            )
        ]


def _has_console_access(iam, user: str) -> tuple[bool | None, str, str]:
    """
    Returns: (has_console_access, note, severity_if_unknown)
    """
    try:
        iam.get_login_profile(UserName=user)
        return True, "LoginProfile present", "INFO"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "NoSuchEntity":
            return False, "No console login profile", "INFO"
        if code in {"AccessDenied", "AccessDeniedException"}:
            return None, "Access denied reading login profile", "MEDIUM"
        return None, f"Error reading login profile: {code}", "MEDIUM"
    except Exception as e:
        return None, f"Error reading login profile: {e}", "MEDIUM"


def _user_has_mfa(iam, user: str) -> tuple[bool | None, str, str]:
    """
    Returns: (mfa_enabled, note, severity_if_unknown)
    """
    try:
        devices = iam.list_mfa_devices(UserName=user).get("MFADevices", [])
        if devices:
            return True, f"{len(devices)} MFA device(s)", "INFO"
        return False, "No MFA devices", "INFO"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException"}:
            return None, "Access denied listing MFA devices", "MEDIUM"
        return None, f"Error listing MFA devices: {code}", "MEDIUM"
    except Exception as e:
        return None, f"Error listing MFA devices: {e}", "MEDIUM"


def _has_administrator_access(iam, user: str) -> tuple[bool | None, str, str]:
    """
    Returns: (has_admin, detail, severity_if_unknown)
    Checks direct user managed policies and group managed policies.
    """
    try:
        # Direct user attachments
        direct = iam.list_attached_user_policies(UserName=user).get("AttachedPolicies", [])
        if any(p.get("PolicyName") == "AdministratorAccess" for p in direct):
            return True, "direct user policy", "INFO"

        # Group attachments
        groups = iam.list_groups_for_user(UserName=user).get("Groups", [])
        for g in groups:
            gname = g.get("GroupName")
            if not gname:
                continue
            gp = iam.list_attached_group_policies(GroupName=gname).get("AttachedPolicies", [])
            if any(p.get("PolicyName") == "AdministratorAccess" for p in gp):
                return True, f"via group {gname}", "INFO"

        return False, "not detected", "INFO"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException"}:
            return None, "Access denied listing attached policies/groups", "MEDIUM"
        return None, f"Error listing policies/groups: {code}", "MEDIUM"
    except Exception as e:
        return None, f"Error listing policies/groups: {e}", "MEDIUM"


def _find_stale_access_keys(
    iam,
    user: str,
    *,
    now: datetime,
    stale_days: int,
) -> list[tuple[str, int, str]]:
    """
    Returns list of tuples: (access_key_id, days_unused, why)
    """
    out: list[tuple[str, int, str]] = []
    try:
        keys = iam.list_access_keys(UserName=user).get("AccessKeyMetadata", [])
        for k in keys:
            if k.get("Status") != "Active":
                continue
            key_id = k.get("AccessKeyId")
            created = k.get("CreateDate")
            if not key_id:
                continue

            last_used_date = None
            try:
                last_used = iam.get_access_key_last_used(AccessKeyId=key_id).get("AccessKeyLastUsed", {})
                last_used_date = last_used.get("LastUsedDate")
            except ClientError:
                # If we can't read last-used, skip (or could report unknown)
                last_used_date = None

            if last_used_date:
                days_unused = int((now - last_used_date).total_seconds() // 86400)
                if days_unused > stale_days:
                    out.append((key_id, days_unused, "since last use"))
            else:
                # Never used or unknown; fall back to age since creation (if available)
                if created:
                    days_unused = int((now - created).total_seconds() // 86400)
                    if days_unused > stale_days:
                        out.append((key_id, days_unused, "no last-used date (created long ago)"))
    except Exception:
        # Best-effort: don't fail whole audit
        return out
    return out


def _check_password_policy(iam) -> list[Finding]:
    try:
        pol = iam.get_account_password_policy()["PasswordPolicy"]
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchEntity"}:
            return [
                Finding(
                    service="IAM",
                    check="PasswordPolicy",
                    severity="LOW",
                    resource="account",
                    message="No account password policy is configured.",
                    recommendation="Configure a strong IAM password policy (length, complexity, rotation as needed).",
                )
            ]
        return [
            Finding(
                service="IAM",
                check="PasswordPolicy",
                severity="MEDIUM",
                resource="account",
                message=f"Failed to read password policy: {code}",
                recommendation="Ensure iam:GetAccountPasswordPolicy is allowed.",
            )
        ]
    except Exception as e:
        return [
            Finding(
                service="IAM",
                check="PasswordPolicy",
                severity="HIGH",
                resource="account",
                message=f"Failed to query IAM (credentials/connection issue): {e}",
                recommendation="Configure AWS credentials (env vars or ~/.aws/credentials) and try again.",
            )
        ]

    issues: list[str] = []
    if pol.get("MinimumPasswordLength", 0) < 14:
        issues.append("MinimumPasswordLength < 14")
    if not pol.get("RequireUppercaseCharacters", False):
        issues.append("RequireUppercaseCharacters is false")
    if not pol.get("RequireLowercaseCharacters", False):
        issues.append("RequireLowercaseCharacters is false")
    if not pol.get("RequireNumbers", False):
        issues.append("RequireNumbers is false")
    if not pol.get("RequireSymbols", False):
        issues.append("RequireSymbols is false")

    if issues:
        return [
            Finding(
                service="IAM",
                check="PasswordPolicy",
                severity="LOW",
                resource="account",
                message=f"Weak password policy settings: {', '.join(issues)}.",
                recommendation="Strengthen IAM password policy or migrate users to AWS SSO/Identity Center.",
            )
        ]

    return [
        Finding(
            service="IAM",
            check="PasswordPolicy",
            severity="INFO",
            resource="account",
            message="Password policy looks reasonable (basic heuristics).",
        )
    ]


