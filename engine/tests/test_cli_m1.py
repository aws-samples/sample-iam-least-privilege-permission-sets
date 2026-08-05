"""CLI collect/analyze 배선 (M1) — moto self-mode end-to-end."""

from __future__ import annotations

import boto3
from moto import mock_aws

from lp2ps.cli import main


def _write_self_config(tmp_path) -> str:
    cfg = tmp_path / "self.yaml"
    cfg.write_text(
        "customer: test\n"
        "region: us-west-2\n"
        "cross_account: false\n"
        "accounts:\n  - self\n",
        encoding="utf-8",
    )
    return str(cfg)


@mock_aws
def test_collect_then_analyze(tmp_path, capsys) -> None:
    iam = boto3.client("iam", region_name="us-west-2")
    iam.create_role(RoleName="r1", AssumeRolePolicyDocument='{"Version":"2012-10-17","Statement":[]}')
    iam.put_role_policy(
        RoleName="r1",
        PolicyName="p",
        PolicyDocument='{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}',
    )

    cfg = _write_self_config(tmp_path)
    out = str(tmp_path / "out")
    common = ["-c", cfg, "--out", out, "--run-id", "run-1", "--started-at", "2026-07-15T00:00:00Z"]

    rc = main(["collect", *common])
    assert rc == 0  # degraded 여도 완주 → 0

    rc = main(["analyze", *common])
    assert rc == 0

    caller = boto3.client("sts", region_name="us-west-2").get_caller_identity()["Account"]
    from lp2ps.storage import LocalFSStorage

    st = LocalFSStorage(out, "test", "run-1")
    assert st.exists("collection_manifest.json")
    assert st.exists("normalized.parquet")
    assert st.exists(f"raw/{caller}/credential_report.json")

    records = st.read_normalized()
    r1 = next(r for r in records if r.principal.endswith("role/r1"))
    assert "s3:GetObject" in r1.granted_actions


@mock_aws
def test_analyze_without_collect_errors(tmp_path) -> None:
    cfg = _write_self_config(tmp_path)
    rc = main(["analyze", "-c", cfg, "--out", str(tmp_path / "out"), "--run-id", "missing"])
    assert rc == 2  # manifest 없음 → 명확한 실패
