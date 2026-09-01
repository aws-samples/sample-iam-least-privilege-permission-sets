"""산출물 저장소 — base URI 해석 (LocalFS / S3).

레이아웃(엔진 모듈 간 계약):
    <base>/<customer>/<run_id>/
        raw/<account_id>/<source>.json      # M1 Collector
        collection_manifest.json            # M1 소스별 ok/degraded/skipped
        normalized.parquet                  # M2 Normalizer = PrincipalRecord[]

base URI:
    - `out` 또는 `/abs/path`   → LocalFS (CLI/로컬 검증)
    - `s3://<bucket>/<prefix>` → S3 (hosted, M3+ 에서 배선)

불변식 ②(결정론): 모든 JSON 은 `sort_keys=True` + 고정 구분자로 직렬화하고, parquet 는
안정 정렬된 레코드로 기록한다. 도구 소유 저장소 쓰기이므로 read-only 가드와 무관하다
(가드는 분석 대상 계정 세션 클라이언트에만 붙는다).

M1 은 LocalFS 만 구현한다. S3 백엔드는 M3(CDK 인프라 배선)에서 같은 인터페이스로 추가한다.
"""

from __future__ import annotations

import io
import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:  # pragma: no cover
    from .models import PrincipalRecord

# 산출물 파일명(계약) — 여러 모듈이 공유하므로 상수로 고정.
MANIFEST_NAME = "collection_manifest.json"
NORMALIZED_NAME = "normalized.parquet"
RAW_DIR = "raw"

# 결정론 JSON 직렬화 옵션(모든 산출물 공통).
_JSON_KW = {"sort_keys": True, "ensure_ascii": False, "indent": 2, "separators": (",", ": ")}


def _dumps(obj: object) -> str:
    """결정론 JSON 직렬화 + 개행 종료(diff 안정)."""
    return json.dumps(obj, **_JSON_KW) + "\n"


class Storage:
    """산출물 저장소 추상 인터페이스."""

    def raw_key(self, account_id: str, source: str) -> str:
        return f"{RAW_DIR}/{account_id}/{source}.json"

    # ---- 하위 클래스가 구현 ----
    def write_json(self, relpath: str, obj: object) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def read_json(self, relpath: str) -> object:  # pragma: no cover - abstract
        raise NotImplementedError

    def write_bytes(self, relpath: str, data: bytes) -> str:  # pragma: no cover - abstract
        raise NotImplementedError

    def read_bytes(self, relpath: str) -> bytes:  # pragma: no cover - abstract
        raise NotImplementedError

    def write_text(self, relpath: str, text: str) -> str:  # pragma: no cover - abstract
        """임의 텍스트 산출물(JSONL/CSV/HCL/HTML). 전체를 한 번에 기록(결정론)."""
        raise NotImplementedError

    def exists(self, relpath: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    def list_accounts(self) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def list_sources(self, account_id: str) -> list[str]:  # pragma: no cover - abstract
        raise NotImplementedError

    def location(self, relpath: str = "") -> str:  # pragma: no cover - abstract
        """사람이 읽을 수 있는 산출물 위치(로그·CLI 출력용)."""
        raise NotImplementedError

    # ---- customer 레벨(run 간 공유) 산출물 — 추이 시계열 등 ----
    def write_shared_json(self, relpath: str, obj: object) -> str:  # pragma: no cover - abstract
        """run 디렉토리 상위(customer 레벨)에 기록 — 여러 run 이 누적 공유하는 산출물용."""
        raise NotImplementedError

    def read_shared_json(self, relpath: str) -> object:  # pragma: no cover - abstract
        raise NotImplementedError

    def shared_exists(self, relpath: str) -> bool:  # pragma: no cover - abstract
        raise NotImplementedError

    # ---- 공통 편의 ----
    def write_raw(self, account_id: str, source: str, obj: object) -> str:
        return self.write_json(self.raw_key(account_id, source), obj)

    def read_raw(self, account_id: str, source: str) -> object:
        return self.read_json(self.raw_key(account_id, source))

    def write_manifest(self, manifest: object) -> str:
        return self.write_json(MANIFEST_NAME, manifest)

    def read_manifest(self) -> object:
        return self.read_json(MANIFEST_NAME)

    def write_normalized(self, records: "list[PrincipalRecord]") -> str:
        """PrincipalRecord[] → parquet(안정 정렬)."""
        return self.write_bytes(NORMALIZED_NAME, records_to_parquet_bytes(records))

    def read_normalized(self) -> "list[PrincipalRecord]":
        from .models import PrincipalRecord

        rows = parquet_bytes_to_rows(self.read_bytes(NORMALIZED_NAME))
        return [PrincipalRecord.model_validate(r) for r in rows]


class LocalFSStorage(Storage):
    """로컬 파일시스템 백엔드 — `<root>/<customer>/<run_id>/`."""

    def __init__(self, base: str | Path, customer: str, run_id: str) -> None:
        self.customer_root = Path(base).expanduser().resolve() / customer
        self.root = self.customer_root / run_id

    def _abs(self, relpath: str) -> Path:
        return self.root / relpath

    def write_json(self, relpath: str, obj: object) -> str:
        p = self._abs(relpath)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_dumps(obj), encoding="utf-8")
        return str(p)

    def read_json(self, relpath: str) -> object:
        return json.loads(self._abs(relpath).read_text(encoding="utf-8"))

    def write_bytes(self, relpath: str, data: bytes) -> str:
        p = self._abs(relpath)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
        return str(p)

    def read_bytes(self, relpath: str) -> bytes:
        return self._abs(relpath).read_bytes()

    def write_shared_json(self, relpath: str, obj: object) -> str:
        p = self.customer_root / relpath
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(_dumps(obj), encoding="utf-8")
        return str(p)

    def read_shared_json(self, relpath: str) -> object:
        return json.loads((self.customer_root / relpath).read_text(encoding="utf-8"))

    def shared_exists(self, relpath: str) -> bool:
        return (self.customer_root / relpath).exists()

    def write_text(self, relpath: str, text: str) -> str:
        p = self._abs(relpath)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        return str(p)

    def exists(self, relpath: str) -> bool:
        return self._abs(relpath).exists()

    def list_accounts(self) -> list[str]:
        raw_root = self._abs(RAW_DIR)
        if not raw_root.is_dir():
            return []
        return sorted(p.name for p in raw_root.iterdir() if p.is_dir())

    def list_sources(self, account_id: str) -> list[str]:
        acct_dir = self._abs(f"{RAW_DIR}/{account_id}")
        if not acct_dir.is_dir():
            return []
        return sorted(p.stem for p in acct_dir.glob("*.json"))

    def location(self, relpath: str = "") -> str:
        return str(self._abs(relpath)) if relpath else str(self.root)


class S3Storage(Storage):
    """S3 백엔드 — `s3://<bucket>/<prefix>/<customer>/<run_id>/`. hosted(Lambda) 모드.

    도구 소유 버킷 쓰기이므로 read-only 가드와 무관(가드는 분석 대상 계정 세션에만). boto3 s3 클라이언트를
    직접 쓴다. LocalFS 와 동일 키 레이아웃 → 코드 경로 동일. 결정론 JSON/parquet 직렬화 재사용.
    """

    def __init__(self, base: str, customer: str, run_id: str) -> None:
        import os

        import boto3

        without = base[len("s3://"):]
        parts = without.split("/", 1)
        self.bucket = parts[0]
        base_prefix = parts[1].strip("/") if len(parts) > 1 and parts[1] else ""
        # customer 레벨(추이 시계열 등) 과 run 레벨 prefix.
        self.customer_prefix = "/".join(p for p in (base_prefix, customer) if p)
        self.run_prefix = f"{self.customer_prefix}/{run_id}"
        self._s3 = boto3.client("s3")
        # 버킷 소유 계정(버킷명과 다른 소스 = env, CDK Stack.account 주입). 설정 시 모든
        # put/get/head/list 에 ExpectedBucketOwner 를 걸어 버킷명 재바인딩·혼동을 방어한다.
        self._owner = os.environ.get("LP2PS_EXPECTED_BUCKET_OWNER", "")
        # put 시 SSE-KMS 명시. 키 ARN 이 주입되면 그 CMK 로 암호화한다.
        self._kms_key_id = os.environ.get("LP2PS_DATA_KEY_ARN", "")

    def _owner_kwargs(self) -> dict:
        return {"ExpectedBucketOwner": self._owner} if self._owner else {}

    def _key(self, relpath: str) -> str:
        return f"{self.run_prefix}/{relpath}"

    def write_json(self, relpath: str, obj: object) -> str:
        return self._put(self._key(relpath), _dumps(obj).encode("utf-8"), "application/json")

    def read_json(self, relpath: str) -> object:
        return json.loads(self._get(self._key(relpath)).decode("utf-8"))

    def write_bytes(self, relpath: str, data: bytes) -> str:
        return self._put(self._key(relpath), data, "application/octet-stream")

    def read_bytes(self, relpath: str) -> bytes:
        return self._get(self._key(relpath))

    def write_text(self, relpath: str, text: str) -> str:
        # Infer Content-Type from the extension: .html must be text/html so the browser renders
        # it (text/plain would show source or download), which the "open report in a new tab via
        # presigned URL" UX depends on. Every text payload is UTF-8 encoded below, so the charset
        # is always declared -- without it the browser guesses (usually latin-1) and non-ASCII
        # characters in generated artifacts (e.g. Terraform comments) render as mojibake.
        ct = "text/html; charset=utf-8" if relpath.endswith(".html") else "text/plain; charset=utf-8"
        return self._put(self._key(relpath), text.encode("utf-8"), ct)

    def exists(self, relpath: str) -> bool:
        return self._head(self._key(relpath))

    def write_shared_json(self, relpath: str, obj: object) -> str:
        key = f"{self.customer_prefix}/{relpath}"
        return self._put(key, _dumps(obj).encode("utf-8"), "application/json")

    def read_shared_json(self, relpath: str) -> object:
        return json.loads(self._get(f"{self.customer_prefix}/{relpath}").decode("utf-8"))

    def shared_exists(self, relpath: str) -> bool:
        return self._head(f"{self.customer_prefix}/{relpath}")

    def list_accounts(self) -> list[str]:
        prefix = f"{self.run_prefix}/{RAW_DIR}/"
        return sorted(self._list_common_prefixes(prefix))

    def list_sources(self, account_id: str) -> list[str]:
        prefix = f"{self.run_prefix}/{RAW_DIR}/{account_id}/"
        keys = self._list_keys(prefix)
        return sorted(
            k[len(prefix):][:-5] for k in keys if k.endswith(".json")
        )

    def location(self, relpath: str = "") -> str:
        key = self._key(relpath) if relpath else self.run_prefix
        return f"s3://{self.bucket}/{key}"

    # ---- boto3 s3 헬퍼 ----
    def _put(self, key: str, data: bytes, content_type: str) -> str:
        # 도구 소유 버킷 쓰기는 반드시 SSE-KMS(CMK) 로 암호화한다. 키 ARN 이 주입되지 않았으면
        # **fail-closed**(무암호 put 금지) — 암호화 없이 저장되는 사고를 원천 차단.
        if not self._kms_key_id:
            raise RuntimeError(
                "LP2PS_DATA_KEY_ARN 미설정 — S3 쓰기를 거부합니다(무암호 저장 방지,). "
                "hosted 배포에선 CDK 가 CMK ARN 을 주입해야 합니다."
            )
        self._s3.put_object(
            Bucket=self.bucket, Key=key, Body=data, ContentType=content_type,
            ServerSideEncryption="aws:kms", SSEKMSKeyId=self._kms_key_id,
            **self._owner_kwargs(),
        )
        return f"s3://{self.bucket}/{key}"

    def _get(self, key: str) -> bytes:
        return self._s3.get_object(Bucket=self.bucket, Key=key, **self._owner_kwargs())["Body"].read()

    def _head(self, key: str) -> bool:
        from botocore.exceptions import ClientError

        try:
            self._s3.head_object(Bucket=self.bucket, Key=key, **self._owner_kwargs())
            return True
        except ClientError:
            return False

    def _list_keys(self, prefix: str) -> list[str]:
        keys: list[str] = []
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, **self._owner_kwargs()):
            keys.extend(o["Key"] for o in page.get("Contents", []))
        return keys

    def _list_common_prefixes(self, prefix: str) -> list[str]:
        out: list[str] = []
        paginator = self._s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix, Delimiter="/", **self._owner_kwargs()):
            for cp in page.get("CommonPrefixes", []):
                sub = cp["Prefix"][len(prefix):].strip("/")
                if sub:
                    out.append(sub)
        return out


def resolve_storage(base: str, customer: str, run_id: str) -> Storage:
    """base URI 를 보고 적절한 Storage 구현을 만든다.

    `s3://<bucket>/<prefix>` → S3 백엔드(hosted). 그 외 → LocalFS(로컬/CLI).
    """
    if base.startswith("s3://"):
        return S3Storage(base, customer, run_id)
    return LocalFSStorage(base, customer, run_id)


# ---- parquet 직렬화 (결정론) ----
def records_to_parquet_bytes(records: "list[PrincipalRecord]") -> bytes:
    """PrincipalRecord[] → parquet 바이트.

    결정론: (account_id, principal) 안정 정렬 후 고정 스키마·행순서로 기록.
    중첩 객체(used_actions 등)는 JSON 문자열 컬럼으로 평탄화해 스키마 추론 흔들림을 없앤다.
    """
    import pyarrow as pa
    import pyarrow.parquet as pq

    ordered = sorted(records, key=lambda r: (r.account_id, r.principal))
    rows = [_encode_row(r.model_dump()) for r in ordered]

    table = pa.Table.from_pylist(rows, schema=_parquet_schema())
    sink = io.BytesIO()
    # 압축 없음 + 통계 off → 실행 간 바이트 안정(타임스탬프·통계 비결정성 제거).
    pq.write_table(
        table,
        sink,
        compression="none",
        write_statistics=False,
        store_schema=True,
    )
    return sink.getvalue()


def parquet_bytes_to_rows(data: bytes) -> list[dict]:
    import pyarrow.parquet as pq

    table = pq.read_table(io.BytesIO(data))
    return [_decode_row(r) for r in table.to_pylist()]


# tags(dict[str,str])는 parquet map 타입으로 왕복시키면 to_pylist() 가 [(k,v)] 튜플 목록을 돌려줘
# pydantic dict 검증에 실패한다. 이 모듈의 다른 중첩 값과 같은 방침으로 **정렬된 JSON 문자열** 컬럼에
# 담는다(sort_keys → 바이트 안정, 불변식 ②).
_JSON_COLUMNS = ("tags",)


def _encode_row(row: dict) -> dict:
    for col in _JSON_COLUMNS:
        row[col] = json.dumps(row.get(col) or {}, sort_keys=True, ensure_ascii=False)
    return row


def _decode_row(row: dict) -> dict:
    for col in _JSON_COLUMNS:
        raw = row.get(col)
        if isinstance(raw, str):
            try:
                row[col] = json.loads(raw) if raw else {}
            except ValueError:
                row[col] = {}
    return row


def _parquet_schema():
    """PrincipalRecord 의 고정 parquet 스키마.

    스키마를 명시해 pyarrow 의 타입 추론(빈 리스트·None 컬럼에서 흔들림)을 제거한다 →
    같은 입력이면 같은 스키마·같은 바이트.

    🔴 이 스키마는 **allowlist** 다. `PrincipalRecord` 에 필드를 추가하고 여기 컬럼을 추가하지 않으면
    `from_pylist` 가 그 키를 조용히 버려, 쓰기는 되는데 읽으면 기본값으로 되돌아온다(에러 없음).
    모델에 필드를 더할 때는 반드시 이 목록도 함께 늘리고 왕복 테스트로 확인할 것.
    """
    import pyarrow as pa

    used_action = pa.struct(
        [
            ("action", pa.string()),
            ("last_used", pa.string()),
            ("count_observed", pa.int64()),
        ]
    )
    escalation = pa.struct(
        [
            ("via", pa.string()),
            ("to", pa.string()),
            ("mitre", pa.string()),
        ]
    )
    return pa.schema(
        [
            ("account_id", pa.string()),
            ("principal", pa.string()),
            ("identity_type", pa.string()),
            ("principal_kind", pa.string()),
            ("trust_principals", pa.list_(pa.string())),
            ("tags", pa.string()),  # 정렬된 JSON 문자열(_JSON_COLUMNS)
            ("granted_actions", pa.list_(pa.string())),
            ("used_actions", pa.list_(used_action)),
            ("used_services", pa.list_(pa.string())),
            ("unused_findings", pa.list_(pa.string())),
            ("undetermined_findings", pa.list_(pa.string())),
            ("mfa", pa.bool_()),
            ("console_login", pa.bool_()),
            ("has_managed_policies", pa.bool_()),
            ("access_key_age_days", pa.int64()),
            ("create_date", pa.string()),
            ("age_days", pa.int64()),
            # IAM 이 추적한 역할 활동(RoleLastUsed) — 스키마에 없으면 정규화 라운드트립에서
            # **조용히 사라진다**(미사용 기간 표기가 이 값에 걸려 있다).
            ("role_last_used", pa.string()),
            ("role_last_used_region", pa.string()),
            ("unused_days", pa.int64()),
            ("observed_days", pa.int64()),
            ("observed_from", pa.string()),
            ("escalation_paths", pa.list_(escalation)),
            ("risk_score", pa.int64()),
            ("risk_level", pa.string()),
            ("risk_reasons", pa.list_(pa.string())),
            ("is_exception", pa.bool_()),
            ("exception_type", pa.string()),
            ("source", pa.list_(pa.string())),
            ("run_id", pa.string()),
            ("ai_suggested", pa.bool_()),
        ]
    )
