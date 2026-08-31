"""storage.py — LocalFS 저장소 + parquet 결정론."""

from __future__ import annotations

from lp2ps.models import PrincipalRecord, UsedAction
from lp2ps.storage import (
    LocalFSStorage,
    resolve_storage,
    records_to_parquet_bytes,
    parquet_bytes_to_rows,
)


def _rec(account: str, principal: str, run_id: str = "run-x") -> PrincipalRecord:
    return PrincipalRecord(
        account_id=account,
        principal=principal,
        identity_type="role",
        granted_actions=["s3:GetObject", "s3:PutObject"],
        used_actions=[UsedAction(action="s3:GetObject", last_used="2026-07-01T00:00:00Z", count_90d=5)],
        used_services=["s3"],
        unused_findings=["s3:PutObject"],
        undetermined_findings=["s3:DeleteObject"],
        source=["credential_report"],
        run_id=run_id,
    )


def test_localfs_layout(tmp_path) -> None:
    st = LocalFSStorage(tmp_path, "acme", "run-1")
    st.write_raw("111122223333", "credential_report", {"a": 1})
    st.write_manifest({"status": "ok"})

    assert st.exists("raw/111122223333/credential_report.json")
    assert st.read_raw("111122223333", "credential_report") == {"a": 1}
    assert st.read_manifest() == {"status": "ok"}
    assert st.list_accounts() == ["111122223333"]
    assert st.list_sources("111122223333") == ["credential_report"]
    # run 별 격리 경로.
    assert str(tmp_path / "acme" / "run-1") == st.location()


def test_json_is_sorted_and_stable(tmp_path) -> None:
    st = LocalFSStorage(tmp_path, "acme", "run-1")
    p = st.write_json("x.json", {"b": 2, "a": 1})
    text = open(p, encoding="utf-8").read()
    # sort_keys → a 가 b 보다 먼저.
    assert text.index('"a"') < text.index('"b"')
    assert text.endswith("\n")


def test_parquet_roundtrip_and_determinism(tmp_path) -> None:
    records = [_rec("222233334444", "arn:b"), _rec("111122223333", "arn:a")]

    b1 = records_to_parquet_bytes(records)
    # 입력 순서를 바꿔도 (account, principal) 안정 정렬 → 동일 바이트.
    b2 = records_to_parquet_bytes(list(reversed(records)))
    assert b1 == b2, "정규화 parquet 는 입력 순서와 무관하게 결정론이어야 한다"

    rows = parquet_bytes_to_rows(b1)
    assert [r["principal"] for r in rows] == ["arn:a", "arn:b"]
    assert rows[0]["used_actions"][0]["action"] == "s3:GetObject"
    # 미사용/판정 불가는 서로 다른 컬럼으로 왕복해야 한다 — 섞이면 UI 가 근거를 잘못 표시한다.
    assert rows[0]["used_services"] == ["s3"]
    assert rows[0]["unused_findings"] == ["s3:PutObject"]
    assert rows[0]["undetermined_findings"] == ["s3:DeleteObject"]


def test_parquet_schema_covers_every_model_field() -> None:
    """parquet 스키마는 allowlist 다 — 모델 필드가 빠지면 조용히 버려진다(에러 없음).

    실제로 principal_kind/trust_principals/tags 를 추가했을 때 스키마를 안 늘려서 쓰기는 되는데
    읽으면 기본값으로 되돌아오는 일이 있었다. 필드 추가를 스키마가 강제하도록 대조한다.
    """
    from lp2ps.models import PrincipalRecord
    from lp2ps.storage import _parquet_schema

    missing = set(PrincipalRecord.model_fields) - set(_parquet_schema().names)
    assert not missing, f"parquet 스키마에 빠진 PrincipalRecord 필드: {sorted(missing)}"


def test_normalized_roundtrip_preserves_kind_and_tags(tmp_path) -> None:
    """신뢰정책 파생 필드와 태그가 parquet 왕복에서 살아남아야 한다."""
    st = LocalFSStorage(tmp_path, "acme", "run-1")
    rec = _rec("111122223333", "arn:a")
    rec.principal_kind = "service"
    rec.trust_principals = ["lambda.amazonaws.com"]
    rec.tags = {"Team": "data", "Env": "prod"}
    st.write_normalized([rec])

    got = st.read_normalized()[0]
    assert got.principal_kind == "service"
    assert got.trust_principals == ["lambda.amazonaws.com"]
    assert got.tags == {"Team": "data", "Env": "prod"}


def test_write_read_normalized(tmp_path) -> None:
    st = LocalFSStorage(tmp_path, "acme", "run-1")
    st.write_normalized([_rec("111122223333", "arn:a")])
    got = st.read_normalized()
    assert len(got) == 1
    assert got[0].principal == "arn:a"
    assert got[0].granted_actions == ["s3:GetObject", "s3:PutObject"]


def _kms_key(region: str = "us-west-2") -> str:
    """moto 에서 CMK 하나 생성해 ARN 반환( put 에 필요)."""
    import boto3

    return boto3.client("kms", region_name=region).create_key()["KeyMetadata"]["Arn"]


def test_s3_storage_roundtrip(monkeypatch) -> None:
    """S3 백엔드 — LocalFS 와 동일 계약(moto). raw/normalized/shared 왕복.

    put 은 SSE-KMS(CMK) + ExpectedBucketOwner 로 저장되어야 한다.
    """
    import boto3
    from moto import mock_aws

    with mock_aws():
        boto3.client("s3", region_name="us-west-2").create_bucket(
            Bucket="lp2ps-test",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        key_arn = _kms_key()
        monkeypatch.setenv("LP2PS_DATA_KEY_ARN", key_arn)
        monkeypatch.setenv("LP2PS_EXPECTED_BUCKET_OWNER", "123456789012")
        st = resolve_storage("s3://lp2ps-test/out", "acme", "run-1")
        from lp2ps.storage import S3Storage

        assert isinstance(st, S3Storage)

        st.write_raw("111122223333", "credential_report", {"a": 1})
        assert st.exists("raw/111122223333/credential_report.json")
        assert st.read_raw("111122223333", "credential_report") == {"a": 1}
        assert st.list_accounts() == ["111122223333"]
        assert st.list_sources("111122223333") == ["credential_report"]

        # 저장된 객체가 실제 aws:kms 로 암호화됐는지 확인.
        head = boto3.client("s3", region_name="us-west-2").head_object(
            Bucket="lp2ps-test", Key="out/acme/run-1/raw/111122223333/credential_report.json"
        )
        assert head.get("ServerSideEncryption") == "aws:kms"
        assert key_arn.split("/")[-1] in head.get("SSEKMSKeyId", "")

        st.write_normalized([_rec("111122223333", "arn:a")])
        got = st.read_normalized()
        assert len(got) == 1 and got[0].principal == "arn:a"

        # customer 레벨 공유(추이 시계열).
        st.write_shared_json("metrics_timeseries.json", [{"run_id": "run-1"}])
        assert st.shared_exists("metrics_timeseries.json")
        assert st.read_shared_json("metrics_timeseries.json") == [{"run_id": "run-1"}]
        assert st.location("catalog.json") == "s3://lp2ps-test/out/acme/run-1/catalog.json"


def test_s3_write_text_always_declares_utf8_charset(monkeypatch) -> None:
    """write_text must declare charset=utf-8 for every text type, not just .html.

    The payload is always UTF-8 encoded. Without the charset the browser guesses (usually
    latin-1) when the object is opened through a presigned URL, so non-ASCII characters in
    generated artifacts (e.g. Terraform comments) render as mojibake.
    """
    import boto3
    from moto import mock_aws

    with mock_aws():
        s3 = boto3.client("s3", region_name="us-west-2")
        s3.create_bucket(
            Bucket="lp2ps-test",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        monkeypatch.setenv("LP2PS_DATA_KEY_ARN", _kms_key())
        st = resolve_storage("s3://lp2ps-test/out", "acme", "run-1")

        st.write_text("iac/permission_sets.tf", "# persona → Permission Set\n")
        st.write_text("report.html", "<html><body>한글</body></html>")

        base = "out/acme/run-1"
        tf_head = s3.head_object(Bucket="lp2ps-test", Key=f"{base}/iac/permission_sets.tf")
        html_head = s3.head_object(Bucket="lp2ps-test", Key=f"{base}/report.html")
        assert tf_head["ContentType"] == "text/plain; charset=utf-8"
        assert html_head["ContentType"] == "text/html; charset=utf-8"


def test_s3_put_fail_closed_without_kms_key(monkeypatch) -> None:
    """LP2PS_DATA_KEY_ARN 미설정이면 S3 put 은 거부(무암호 저장 방지)."""
    import boto3
    import pytest
    from moto import mock_aws

    with mock_aws():
        boto3.client("s3", region_name="us-west-2").create_bucket(
            Bucket="lp2ps-test",
            CreateBucketConfiguration={"LocationConstraint": "us-west-2"},
        )
        monkeypatch.delenv("LP2PS_DATA_KEY_ARN", raising=False)
        st = resolve_storage("s3://lp2ps-test/out", "acme", "run-1")
        with pytest.raises(RuntimeError, match="LP2PS_DATA_KEY_ARN"):
            st.write_raw("111122223333", "credential_report", {"a": 1})
