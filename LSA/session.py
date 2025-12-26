from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import boto3
from boto3.session import Session


@dataclass(frozen=True)
class AwsContext:
    session: Session
    account_id: Optional[str]
    region: Optional[str]


def create_boto3_session(profile: Optional[str] = None, region: Optional[str] = None) -> Session:
    """
    Create a boto3 Session.

    If profile is None, boto3 will use the default credential chain:
    env vars, default profile, SSO/role/instance metadata, etc.
    """
    kwargs = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.Session(**kwargs)


def resolve_account_id(session: Session) -> Optional[str]:
    try:
        sts = session.client("sts")
        return sts.get_caller_identity().get("Account")
    except Exception:
        return None


def build_aws_context(profile: Optional[str] = None, region: Optional[str] = None) -> AwsContext:
    session = create_boto3_session(profile=profile, region=region)
    resolved_region = region or session.region_name
    account_id = resolve_account_id(session)
    return AwsContext(session=session, account_id=account_id, region=resolved_region)


