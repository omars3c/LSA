from __future__ import annotations

from ipaddress import ip_network

from botocore.exceptions import ClientError

from LSA.reporting import Finding
from LSA.session import AwsContext
from checks.ec2_security_groups import audit_security_groups


SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    9200: "Elasticsearch",
    27017: "MongoDB",
}


def run_ec2_checks(ctx: AwsContext) -> list[Finding]:
    # EC2 is region-scoped; if no region is resolved, we can’t do much.
    if not ctx.region:
        return [
            Finding(
                service="EC2",
                check="RegionResolved",
                severity="HIGH",
                resource="*",
                message="No region could be resolved. Provide --region or set AWS_REGION/AWS_DEFAULT_REGION.",
            )
        ]

    ec2 = ctx.session.client("ec2", region_name=ctx.region)
    findings: list[Finding] = []

    findings.extend(_check_security_groups_open_ports(ec2))
    findings.extend(_check_instances_imdsv1(ec2))

    return findings


def _check_security_groups_open_ports(ec2) -> list[Finding]:
    findings: list[Finding] = []
    try:
        paginator = ec2.get_paginator("describe_security_groups")
        for page in paginator.paginate():
            for sg in page.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "<unknown>")
                sg_name = sg.get("GroupName", "")
                label = f"{sg_id} ({sg_name})" if sg_name else sg_id

                for perm in sg.get("IpPermissions", []):
                    from_p = perm.get("FromPort")
                    to_p = perm.get("ToPort")
                    ip_proto = perm.get("IpProtocol")
                    # For -1/all protocols, treat as high risk if open to world

                    world_v4 = any(_is_world(c.get("CidrIp")) for c in perm.get("IpRanges", []))
                    world_v6 = any(_is_world(c.get("CidrIpv6")) for c in perm.get("Ipv6Ranges", []))
                    if not (world_v4 or world_v6):
                        continue

                    if ip_proto == "-1":
                        findings.append(
                            Finding(
                                service="EC2",
                                check="SecurityGroupOpenToWorld",
                                severity="HIGH",
                                resource=label,
                                message="Inbound rule allows ALL protocols from the Internet (0.0.0.0/0 or ::/0).",
                                recommendation="Restrict inbound rules to known IPs/VPC CIDRs, or use SSM / bastion.",
                            )
                        )
                        continue

                    if from_p is None or to_p is None:
                        # Non-TCP/UDP (e.g., ICMP) - still flag if world-open
                        findings.append(
                            Finding(
                                service="EC2",
                                check="SecurityGroupOpenToWorld",
                                severity="MEDIUM",
                                resource=label,
                                message=f"Inbound rule ({ip_proto}) is open to the Internet.",
                                recommendation="Restrict inbound rules to required sources only.",
                            )
                        )
                        continue

                    # Focus on sensitive ports first
                    for port, name in SENSITIVE_PORTS.items():
                        if from_p <= port <= to_p:
                            findings.append(
                                Finding(
                                    service="EC2",
                                    check="SecurityGroupOpenToWorld",
                                    severity="HIGH",
                                    resource=label,
                                    message=f"{name} port {port} is open to the Internet.",
                                    recommendation="Restrict the rule to trusted IPs, or remove public exposure.",
                                )
                            )

                    # Generic open range
                    if (to_p - from_p) >= 1000:
                        findings.append(
                            Finding(
                                service="EC2",
                                check="SecurityGroupOpenToWorld",
                                severity="MEDIUM",
                                resource=label,
                                message=f"Large port range {from_p}-{to_p} open to the Internet.",
                                recommendation="Limit exposure to required ports and trusted sources.",
                            )
                        )

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        return [
            Finding(
                service="EC2",
                check="DescribeSecurityGroups",
                severity="HIGH",
                resource="*",
                message=f"Failed to describe security groups: {code}",
                recommendation="Ensure ec2:DescribeSecurityGroups is allowed.",
            )
        ]
    except Exception as e:
        return [
            Finding(
                service="EC2",
                check="DescribeSecurityGroups",
                severity="HIGH",
                resource="*",
                message=f"Failed to describe security groups: {e}",
            )
        ]

    if not findings:
        findings.append(
            Finding(
                service="EC2",
                check="SecurityGroupOpenToWorld",
                severity="INFO",
                resource="*",
                message="No obvious world-open inbound rules detected (heuristic).",
            )
        )

    return findings


def _check_instances_imdsv1(ec2) -> list[Finding]:
    findings: list[Finding] = []
    try:
        paginator = ec2.get_paginator("describe_instances")
        any_instances = False
        for page in paginator.paginate():
            for res in page.get("Reservations", []):
                for inst in res.get("Instances", []):
                    any_instances = True
                    instance_id = inst.get("InstanceId", "<unknown>")
                    md = inst.get("MetadataOptions", {})
                    # If HttpTokens is optional, IMDSv1 is allowed.
                    tokens = (md.get("HttpTokens") or "").lower()
                    if tokens != "required":
                        findings.append(
                            Finding(
                                service="EC2",
                                check="IMDSv1Allowed",
                                severity="MEDIUM",
                                resource=instance_id,
                                message="Instance allows IMDSv1 (HttpTokens is not 'required').",
                                recommendation="Set instance metadata option HttpTokens=required to enforce IMDSv2.",
                            )
                        )

        if not any_instances:
            findings.append(
                Finding(
                    service="EC2",
                    check="InstancesPresent",
                    severity="INFO",
                    resource="*",
                    message="No EC2 instances found in this region.",
                )
            )

    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        return [
            Finding(
                service="EC2",
                check="DescribeInstances",
                severity="HIGH",
                resource="*",
                message=f"Failed to describe instances: {code}",
                recommendation="Ensure ec2:DescribeInstances is allowed (and that you selected the correct region).",
            )
        ]
    except Exception as e:
        return [
            Finding(
                service="EC2",
                check="DescribeInstances",
                severity="HIGH",
                resource="*",
                message=f"Failed to describe instances: {e}",
            )
        ]

    if not any(f.check == "IMDSv1Allowed" for f in findings):
        findings.append(
            Finding(
                service="EC2",
                check="IMDSv1Allowed",
                severity="INFO",
                resource="*",
                message="No instances found that obviously allow IMDSv1 (based on MetadataOptions).",
            )
        )

    return findings


def _is_world(cidr: str | None) -> bool:
    if not cidr:
        return False
    try:
        net = ip_network(cidr, strict=False)
        return str(net) in {"0.0.0.0/0", "::/0"}
    except Exception:
        return False


