"""IAM MFA and S3 versioning checks of the AWS collector, against moto and fakes."""

from unittest.mock import MagicMock

import boto3
from botocore.exceptions import ClientError
from moto import mock_aws

from collectors.aws.iam_checks import check_iam_mfa
from collectors.aws.s3_checks import check_s3_versioning

TAG = [{"Key": "trust-portal:backup", "Value": "versioning"}]


def _session():
    return boto3.Session(region_name="us-east-1")


def _console_user(iam, name, mfa=False):
    iam.create_user(UserName=name)
    iam.create_login_profile(UserName=name, Password="Aa1!aaaaaaaaaaaa")
    if mfa:
        device = iam.create_virtual_mfa_device(VirtualMFADeviceName=name)["VirtualMFADevice"]
        iam.enable_mfa_device(UserName=name, SerialNumber=device["SerialNumber"],
                              AuthenticationCode1="123456", AuthenticationCode2="654321")


@mock_aws
def test_mfa_checks_only_console_users():
    iam = boto3.client("iam", region_name="us-east-1")
    _console_user(iam, "with-mfa", mfa=True)
    _console_user(iam, "without-mfa")
    iam.create_user(UserName="service-user")
    iam.create_access_key(UserName="service-user")

    results = {r.check_name: r.status for r in check_iam_mfa(_session())}

    assert results == {"iam_mfa:with-mfa": "pass", "iam_mfa:without-mfa": "fail"}


@mock_aws
def test_mfa_with_no_console_users_is_one_neutral_pass():
    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="service-user")

    results = check_iam_mfa(_session())

    assert [(r.check_name, r.status) for r in results] == [("iam_mfa", "pass")]
    assert "console password" in results[0].message
    assert results[0].target_test_name == "Multi-factor authentication enabled for all users"


def _fake_iam_session(login_profile_errors):
    iam = MagicMock()
    iam.list_users.return_value = {"Users": [{"UserName": "ok"}, {"UserName": "broken"}]}

    def login_profile(UserName):
        if UserName in login_profile_errors:
            raise ClientError({"Error": {"Code": login_profile_errors[UserName],
                                         "Message": "x"}}, "GetLoginProfile")

    iam.get_login_profile.side_effect = login_profile
    iam.list_mfa_devices.return_value = {"MFADevices": [{"SerialNumber": "s"}]}
    session = MagicMock()
    session.client.return_value = iam
    return session


def test_mfa_error_for_one_user_is_an_error_result_for_that_user():
    session = _fake_iam_session({"broken": "AccessDenied"})

    results = {r.check_name: r.status for r in check_iam_mfa(session)}

    assert results == {"iam_mfa:ok": "pass", "iam_mfa:broken": "error"}


def test_mfa_no_such_entity_means_no_console_password():
    session = _fake_iam_session({"broken": "NoSuchEntity"})

    results = {r.check_name: r.status for r in check_iam_mfa(session)}

    assert results == {"iam_mfa:ok": "pass"}


def _bucket(s3, name, versioned=False, tags=None):
    s3.create_bucket(Bucket=name)
    if versioned:
        s3.put_bucket_versioning(Bucket=name, VersioningConfiguration={"Status": "Enabled"})
    if tags is not None:
        s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": tags})


@mock_aws
def test_versioning_checks_only_tagged_buckets():
    s3 = boto3.client("s3", region_name="us-east-1")
    _bucket(s3, "tagged-on", versioned=True, tags=TAG)
    _bucket(s3, "tagged-off", tags=TAG)
    _bucket(s3, "untagged-off")
    _bucket(s3, "other-tag", tags=[{"Key": "trust-portal:backup", "Value": "other"}])

    results = {r.check_name: r.status for r in check_s3_versioning(_session())}

    assert results == {"s3_versioning:tagged-on": "pass", "s3_versioning:tagged-off": "fail"}


@mock_aws
def test_versioning_with_no_tagged_bucket_is_one_fail():
    s3 = boto3.client("s3", region_name="us-east-1")
    _bucket(s3, "build-logs-bucket", versioned=True)

    results = check_s3_versioning(_session())

    assert [(r.check_name, r.status) for r in results] == [("s3_versioning", "fail")]
    assert "trust-portal:backup=versioning" in results[0].message
    assert "backup policy" in results[0].message


def test_versioning_tag_read_error_is_an_error_for_that_bucket():
    s3 = MagicMock()
    s3.list_buckets.return_value = {"Buckets": [{"Name": "locked"}]}
    s3.get_bucket_tagging.side_effect = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": "x"}}, "GetBucketTagging")
    session = MagicMock()
    session.client.return_value = s3

    results = check_s3_versioning(session)

    assert [(r.check_name, r.status) for r in results] == [("s3_versioning:locked", "error")]
