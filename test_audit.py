from __future__ import annotations

import boto3
from moto import mock_aws
from rich.console import Console

from checks.ec2 import audit_security_groups
from checks.iam_entry import audit_iam
from checks.s3_entry import audit_s3
from LSA.session import AwsContext


@mock_aws
def test_audit_security_groups_prints_warning() -> None:
    """
    Creates:
    - vulnerable SG: SSH 22 open to 0.0.0.0/0
    - safe SG: no world-open ingress

    Runs audit_security_groups and asserts it prints a warning.
    """
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    ec2 = session.client("ec2", region_name=region)

    # Moto EC2 requires a VPC for SG creation.
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]

    # Vulnerable SG
    vuln_sg_id = ec2.create_security_group(
        GroupName="vuln-ssh-open",
        Description="SSH open to world",
        VpcId=vpc_id,
    )["GroupId"]
    ec2.authorize_security_group_ingress(
        GroupId=vuln_sg_id,
        IpProtocol="tcp",
        FromPort=22,
        ToPort=22,
        CidrIp="0.0.0.0/0",
    )

    # Safe SG
    safe_sg_id = ec2.create_security_group(
        GroupName="safe-no-open-ingress",
        Description="No world-open ingress",
        VpcId=vpc_id,
    )["GroupId"]
    # (no ingress rules added)

    ctx = AwsContext(session=session, account_id="000000000000", region=region)

    console = Console(record=True, width=120, force_terminal=True)
    findings = audit_security_groups(ctx, console=console)

    output = console.export_text()
    print("\n=== Captured audit output ===\n")
    print(output)

    # Assert: vulnerable SG must be flagged and printed
    assert vuln_sg_id in output, "Expected vulnerable security group ID in output"
    assert "0.0.0.0/0" in output, "Expected world-open CIDR in output"
    assert "22" in output, "Expected SSH port in output"
    assert any(f.resource == vuln_sg_id for f in findings), "Expected findings to include vulnerable SG"

    # Assert: safe SG should NOT be reported as world-open
    assert safe_sg_id not in output, "Did not expect safe security group ID in output"


@mock_aws
def test_s3_audit_marks_public_bucket() -> None:
    """
    Creates:
    - an S3 bucket with ACL 'public-read' (vulnerable)

    Runs audit_s3 and asserts it prints Public and/or High risk.
    """
    region = "us-east-1"
    session = boto3.Session(region_name=region)
    s3 = session.client("s3", region_name=region)

    bucket = "lca-moto-public-read-bucket"

    # us-east-1 special-case: do not provide CreateBucketConfiguration
    s3.create_bucket(Bucket=bucket)

    # Emulate vulnerability via ACL
    s3.put_bucket_acl(Bucket=bucket, ACL="public-read")

    ctx = AwsContext(session=session, account_id="000000000000", region=region)
    console = Console(record=True, width=120, force_terminal=True)

    audit_s3(ctx, console=console)

    output = console.export_text()
    print("\n=== Captured S3 audit output ===\n")
    print(output)

    assert bucket in output, "Expected bucket name in output"
    assert ("Public" in output) or ("High" in output) or ("HIGH" in output), "Expected audit to mark bucket as Public/High Risk"


@mock_aws
def test_iam_audit_marks_missing_mfa_as_critical() -> None:
    """
    Creates:
    - user 'admin-no-mfa' with NO MFA devices (should be CRITICAL)
    - user 'secure-user' with a virtual MFA device attached (should be OK/green)
    """
    session = boto3.Session(region_name="us-east-1")
    iam = session.client("iam")

    iam.create_user(UserName="admin-no-mfa")

    iam.create_user(UserName="secure-user")
    v = iam.create_virtual_mfa_device(VirtualMFADeviceName="secure-user-mfa")
    serial = v["VirtualMFADevice"]["SerialNumber"]
    # Moto accepts dummy auth codes for enable_mfa_device
    iam.enable_mfa_device(
        UserName="secure-user",
        SerialNumber=serial,
        AuthenticationCode1="123456",
        AuthenticationCode2="654321",
    )

    ctx = AwsContext(session=session, account_id="000000000000", region="us-east-1")
    console = Console(record=True, width=120, force_terminal=True)

    audit_iam(ctx, console=console)

    output = console.export_text()
    print("\n=== Captured IAM audit output ===\n")
    print(output)

    assert "admin-no-mfa" in output, "Expected admin-no-mfa in output"
    assert "CRITICAL" in output, "Expected CRITICAL risk marker in output"

    # secure-user should not be CRITICAL
    lines = [ln for ln in output.splitlines() if "secure-user" in ln]
    assert lines, "Expected secure-user row in output"
    assert all("CRITICAL" not in ln for ln in lines), "Did not expect secure-user to be marked CRITICAL"


if __name__ == "__main__":
    test_audit_security_groups_prints_warning()
    print("\nOK: audit_security_groups flagged the vulnerable SG and produced output.\n")
    test_s3_audit_marks_public_bucket()
    print("\nOK: audit_s3 flagged the public-read bucket and produced output.\n")
    test_iam_audit_marks_missing_mfa_as_critical()
    print("\nOK: audit_iam flagged missing MFA as CRITICAL and produced output.\n")


