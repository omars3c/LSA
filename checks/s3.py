from __future__ import annotations

from typing import Iterable

from botocore.exceptions import ClientError

from LSA.reporting import Finding
from LSA.session import AwsContext
from rich.console import Console
from rich.table import Table


def run_s3_checks(ctx: AwsContext) -> list[Finding]:
    s3 = ctx.session.client("s3")
    findings: list[Finding] = []

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        return [
            Finding(
                service="S3",
                check="ListBuckets",
                severity="HIGH",
                resource="*",
                message=f"Failed to list buckets: {e}",
                recommendation="Ensure your credentials allow s3:ListAllMyBuckets.",
            )
        ]

    for b in buckets:
        name = b.get("Name", "<unknown>")

        findings.extend(_check_public_access_block(s3, name))
        findings.extend(_check_encryption(s3, name))
        findings.extend(_check_versioning(s3, name))
        findings.extend(_check_policy_status(s3, name))

    if not buckets:
        findings.append(
            Finding(
                service="S3",
                check="BucketsPresent",
                severity="INFO",
                resource="*",
                message="No buckets found in this account.",
            )
        )

    return findings


def _check_public_access_block(s3, bucket: str) -> Iterable[Finding]:
    try:
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        required_true = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        missing = [k for k in required_true if not pab.get(k, False)]
        if missing:
            yield Finding(
                service="S3",
                check="PublicAccessBlock",
                severity="HIGH",
                resource=bucket,
                message=f"Public Access Block not fully enabled (false: {', '.join(missing)}).",
                recommendation="Enable all Public Access Block settings on the bucket (and ideally at account level).",
            )
        else:
            yield Finding(
                service="S3",
                check="PublicAccessBlock",
                severity="INFO",
                resource=bucket,
                message="Public Access Block is fully enabled.",
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
            yield Finding(
                service="S3",
                check="PublicAccessBlock",
                severity="HIGH",
                resource=bucket,
                message="No Public Access Block configuration found.",
                recommendation="Enable Public Access Block on the bucket (and ideally at account level).",
            )
        elif code in {"AccessDenied", "AccessDeniedException"}:
            yield Finding(
                service="S3",
                check="PublicAccessBlock",
                severity="MEDIUM",
                resource=bucket,
                message="Access denied reading Public Access Block configuration.",
                recommendation="Allow s3:GetPublicAccessBlock to audit this check.",
            )
        else:
            yield Finding(
                service="S3",
                check="PublicAccessBlock",
                severity="LOW",
                resource=bucket,
                message=f"Failed to read Public Access Block: {code}",
            )


def _check_encryption(s3, bucket: str) -> Iterable[Finding]:
    try:
        enc = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
        if not enc:
            yield Finding(
                service="S3",
                check="DefaultEncryption",
                severity="HIGH",
                resource=bucket,
                message="Default encryption rules are empty.",
                recommendation="Enable default encryption (SSE-S3 or SSE-KMS) for the bucket.",
            )
            return
        yield Finding(
            service="S3",
            check="DefaultEncryption",
            severity="INFO",
            resource=bucket,
            message="Default encryption is configured.",
        )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"ServerSideEncryptionConfigurationNotFoundError"}:
            yield Finding(
                service="S3",
                check="DefaultEncryption",
                severity="HIGH",
                resource=bucket,
                message="Default bucket encryption is not configured.",
                recommendation="Enable default encryption (SSE-S3 or SSE-KMS).",
            )
        elif code in {"AccessDenied", "AccessDeniedException"}:
            yield Finding(
                service="S3",
                check="DefaultEncryption",
                severity="MEDIUM",
                resource=bucket,
                message="Access denied reading bucket encryption.",
                recommendation="Allow s3:GetEncryptionConfiguration to audit this check.",
            )
        else:
            yield Finding(
                service="S3",
                check="DefaultEncryption",
                severity="LOW",
                resource=bucket,
                message=f"Failed to read bucket encryption: {code}",
            )


def _check_versioning(s3, bucket: str) -> Iterable[Finding]:
    try:
        v = s3.get_bucket_versioning(Bucket=bucket)
        status = v.get("Status", "Disabled")
        if status != "Enabled":
            yield Finding(
                service="S3",
                check="Versioning",
                severity="LOW",
                resource=bucket,
                message=f"Bucket versioning is {status}.",
                recommendation="Enable versioning for better recovery/ransomware resilience (where appropriate).",
            )
        else:
            yield Finding(
                service="S3",
                check="Versioning",
                severity="INFO",
                resource=bucket,
                message="Bucket versioning is enabled.",
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException"}:
            yield Finding(
                service="S3",
                check="Versioning",
                severity="MEDIUM",
                resource=bucket,
                message="Access denied reading bucket versioning.",
                recommendation="Allow s3:GetBucketVersioning to audit this check.",
            )
        else:
            yield Finding(
                service="S3",
                check="Versioning",
                severity="LOW",
                resource=bucket,
                message=f"Failed to read bucket versioning: {code}",
            )


def _check_policy_status(s3, bucket: str) -> Iterable[Finding]:
    # A light-weight signal if AWS deems the bucket "public" via policy analysis
    try:
        st = s3.get_bucket_policy_status(Bucket=bucket)["PolicyStatus"]
        if st.get("IsPublic", False):
            yield Finding(
                service="S3",
                check="PolicyStatus",
                severity="HIGH",
                resource=bucket,
                message="Bucket policy status indicates the bucket is public.",
                recommendation="Review and restrict bucket policy; use Public Access Block; remove public statements.",
            )
        else:
            yield Finding(
                service="S3",
                check="PolicyStatus",
                severity="INFO",
                resource=bucket,
                message="Bucket policy status does not indicate public access.",
            )
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        # If there is no policy, AWS may return NoSuchBucketPolicy for other calls,
        # but policy status can still fail under limited perms.
        if code in {"AccessDenied", "AccessDeniedException"}:
            yield Finding(
                service="S3",
                check="PolicyStatus",
                severity="MEDIUM",
                resource=bucket,
                message="Access denied reading bucket policy status.",
                recommendation="Allow s3:GetBucketPolicyStatus to audit this check.",
            )
        else:
            yield Finding(
                service="S3",
                check="PolicyStatus",
                severity="LOW",
                resource=bucket,
                message=f"Failed to read bucket policy status: {code}",
            )


def audit_s3_buckets(ctx: AwsContext, *, console: Console | None = None) -> list[Finding]:
    """
    Fast, admin-friendly S3 audit:
    - list all buckets
    - for each bucket check Public Access Block, ACL, and default encryption
    - print per-bucket status in red/green (rich)

    Returns findings as well (so main can keep summary/exit codes).
    """
    s3 = ctx.session.client("s3")
    findings: list[Finding] = []

    try:
        buckets = [b.get("Name", "<unknown>") for b in s3.list_buckets().get("Buckets", [])]
    except Exception as e:
        f = Finding(
            service="S3",
            check="ListBuckets",
            severity="HIGH",
            resource="*",
            message=f"Failed to list buckets: {e}",
            recommendation="Ensure your credentials allow s3:ListAllMyBuckets.",
        )
        if console:
            console.print(f"[bold red]S3[/] {f.message}")
        return [f]

    table: Table | None = None
    if console:
        table = Table(title="S3 Bucket Audit", show_lines=False)
        table.add_column("Bucket", style="white")
        table.add_column("PublicAccessBlock", style="white")
        table.add_column("ACL", style="white")
        table.add_column("Encryption", style="white")
        table.add_column("Overall", style="white")

    if not buckets:
        f = Finding(
            service="S3",
            check="BucketsPresent",
            severity="INFO",
            resource="*",
            message="No buckets found in this account.",
        )
        if console:
            console.print("[green]S3: no buckets found.[/]")
        return [f]

    for bucket in buckets:
        pab_ok, pab_note, pab_sev = _pab_status(s3, bucket)
        acl_public, acl_note, acl_sev = _acl_status(s3, bucket)
        enc_ok, enc_note, enc_sev = _encryption_status(s3, bucket)

        is_public = (not pab_ok) or acl_public
        enc_disabled = not enc_ok
        risky = is_public or enc_disabled

        overall_style = "bold red" if risky else "green"
        overall_text = "RISK" if risky else "OK"

        if table is not None:
            pab_style = "green" if pab_ok else ("bold red" if pab_sev == "HIGH" else "yellow")
            acl_style = "bold red" if acl_public else ("yellow" if acl_sev == "MEDIUM" else "green")
            enc_style = "green" if enc_ok else ("bold red" if enc_sev == "HIGH" else "yellow")

            table.add_row(
                f"[{overall_style}]{bucket}[/{overall_style}]",
                f"[{pab_style}]{pab_note}[/{pab_style}]",
                f"[{acl_style}]{acl_note}[/{acl_style}]",
                f"[{enc_style}]{enc_note}[/{enc_style}]",
                f"[{overall_style}]{overall_text}[/{overall_style}]",
            )

        if risky:
            msg_parts: list[str] = []
            if is_public:
                msg_parts.append("bucket may be public")
            if enc_disabled:
                msg_parts.append("default encryption is not enabled")
            findings.append(
                Finding(
                    service="S3",
                    check="BucketRisk",
                    severity="HIGH",
                    resource=bucket,
                    message="; ".join(msg_parts) + ".",
                    recommendation="Enable Public Access Block, remove public ACL grants, and enable default encryption.",
                )
            )
        else:
            findings.append(
                Finding(
                    service="S3",
                    check="BucketRisk",
                    severity="INFO",
                    resource=bucket,
                    message="Bucket looks safe (PAB enabled, no public ACL grants, encryption enabled).",
                )
            )

    if console and table is not None:
        console.print(table)
        console.print()

    return findings


def _pab_status(s3, bucket: str) -> tuple[bool, str, str]:
    """
    Returns: (pab_ok, note, severity_if_not_ok)
    """
    try:
        pab = s3.get_public_access_block(Bucket=bucket)["PublicAccessBlockConfiguration"]
        required_true = [
            "BlockPublicAcls",
            "IgnorePublicAcls",
            "BlockPublicPolicy",
            "RestrictPublicBuckets",
        ]
        missing = [k for k in required_true if not pab.get(k, False)]
        if missing:
            return False, f"NOT FULL ({', '.join(missing)})", "HIGH"
        return True, "ENABLED", "INFO"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"NoSuchPublicAccessBlockConfiguration", "NoSuchPublicAccessBlock"}:
            return False, "MISSING", "HIGH"
        if code in {"AccessDenied", "AccessDeniedException"}:
            return False, "ACCESS DENIED", "MEDIUM"
        return False, f"ERROR ({code})", "MEDIUM"
    except Exception:
        return False, "ERROR", "MEDIUM"


def _acl_status(s3, bucket: str) -> tuple[bool, str, str]:
    """
    Returns: (acl_public, note, severity_if_problem)
    """
    try:
        acl = s3.get_bucket_acl(Bucket=bucket)
        grants = acl.get("Grants", [])
        public_grants = _find_public_acl_grants(grants)
        if public_grants:
            return True, f"PUBLIC ({', '.join(public_grants)})", "HIGH"
        return False, "NO PUBLIC GRANTS", "INFO"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"AccessDenied", "AccessDeniedException"}:
            return False, "ACCESS DENIED", "MEDIUM"
        return False, f"ERROR ({code})", "MEDIUM"
    except Exception:
        return False, "ERROR", "MEDIUM"


def _find_public_acl_grants(grants: list[dict]) -> list[str]:
    """
    Detect public ACL grants (AllUsers / AuthenticatedUsers).
    Returns a list of short descriptors for display.
    """
    out: list[str] = []
    for g in grants:
        grantee = g.get("Grantee", {}) or {}
        uri = (grantee.get("URI") or "").lower()
        perm = (g.get("Permission") or "UNKNOWN").upper()
        if "allusers" in uri:
            out.append(f"AllUsers:{perm}")
        elif "authenticatedusers" in uri:
            out.append(f"AuthUsers:{perm}")
    return out


def _encryption_status(s3, bucket: str) -> tuple[bool, str, str]:
    """
    Returns: (encryption_ok, note, severity_if_not_ok)
    """
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket)["ServerSideEncryptionConfiguration"]["Rules"]
        if not rules:
            return False, "EMPTY", "HIGH"
        return True, "ENABLED", "INFO"
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in {"ServerSideEncryptionConfigurationNotFoundError"}:
            return False, "NOT ENABLED", "HIGH"
        if code in {"AccessDenied", "AccessDeniedException"}:
            return False, "ACCESS DENIED", "MEDIUM"
        return False, f"ERROR ({code})", "MEDIUM"
    except Exception:
        return False, "ERROR", "MEDIUM"

