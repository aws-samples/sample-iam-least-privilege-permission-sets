"""읽기 모델 — 도구 소유 DynamoDB/S3 에서 읽기만(순수 read).

엔진 `lp2ps.storage.S3Storage` 와 `lp2ps.models` 를 재사용해 계약 일치를 보장한다. 최신 run 을
runs 테이블에서 찾아 그 run 의 S3 산출물(catalog/cleanup/normalized)을 읽는다. 지표는 metrics
테이블에서 시계열로 읽는다.

쓰기는 여기 없다(POST /runs 의 SFN 트리거, approve 의 catalog 갱신은 router 에서 도구 소유 리소스만).
"""

from __future__ import annotations

from typing import Any

import boto3
from boto3.dynamodb.conditions import Key

from lp2ps.models import CatalogEntry, CleanupItem, MetricsPoint, PolicyAction, Run
from lp2ps.storage import S3Storage

from .deps import Settings


class CatalogConflict(Exception):
    """catalog override 낙관적 락 충돌(동시 쓰기) — 라우터가 409 로 변환."""


def _member_hash(members: list[str]) -> str:
    """persona 멤버셋 지문. 멤버셋이 바뀌면 승인 상속을 무효화하는 데 쓴다.

    비교용이지만 truncate(64bit) 하지 않고 **전체 SHA-256 digest**를 쓴다(충돌 여지 제거)."""
    import hashlib

    joined = "\n".join(sorted(members))
    return hashlib.sha256(joined.encode("utf-8")).hexdigest()


class Repositories:
    def __init__(self, settings: Settings) -> None:
        from botocore.config import Config as BotoConfig

        self.s = settings
        self._ddb = boto3.resource("dynamodb", region_name=settings.region)
        # SSE-KMS 버킷 presigned URL 요구사항:
        #  (1) SigV4 서명 필수(KMS 객체) — 아니면 400 InvalidArgument.
        #  (2) **리전 엔드포인트 명시** — 글로벌 s3.amazonaws.com 로 만들면 307 리다이렉트 시
        #      호스트가 바뀌어 SignatureDoesNotMatch(403). 리전 호스트로 고정해 리다이렉트 제거.
        self._s3 = boto3.client(
            "s3",
            region_name=settings.region,
            endpoint_url=f"https://s3.{settings.region}.amazonaws.com",
            config=BotoConfig(signature_version="s3v4", s3={"addressing_style": "virtual"}),
        )

    # ---- runs (DynamoDB) ----
    def list_runs(self) -> list[Run]:
        items = self._scan(self.s.runs_table)
        runs = [Run.model_validate(_from_ddb(i)) for i in items]
        # 최신순(started_at desc) — Run.started_at 은 ISO8601.
        runs.sort(key=lambda r: r.started_at, reverse=True)
        return runs

    def latest_run_id(self) -> str | None:
        """산출물 조회의 기준이 되는 **최신 완료 run**. 진행 중 run 은 건너뛴다.

        POST /runs 는 실행을 트리거한 즉시 status="running" 레코드를 넣는다(진행 상태를 관측
        가능하게 만들기 위해 — routers/runs.py `_record_running`). 그 run 의 S3 산출물은 파이프라인이
        끝날 때까지 존재하지 않으므로, '최신'을 단순히 started_at 최댓값으로 잡으면 조회가 도는
        수 분 동안 catalog·cleanup·accounts 가 빈 목록이 되고 /reports 는 404 가 된다 — 이전 완료
        결과가 멀쩡히 있는데도 화면에서 사라진다.

        따라서 여기서는 종료 상태(succeeded/degraded/failed)인 run 만 후보로 본다. failed 도
        포함하는데, 실패한 run 도 부분 산출물을 남기며 그게 그 시점의 최신 관측이기 때문이다
        (진행 중 run 만 산출물이 아예 없다).
        """
        runs = self.list_runs()
        return next((r.run_id for r in runs if r.status != "running"), None)

    # ---- metrics (DynamoDB) ----
    def list_metrics(self) -> list[MetricsPoint]:
        items = self._scan(self.s.metrics_table)
        points = [MetricsPoint.model_validate(_from_ddb(i)) for i in items]
        points.sort(key=lambda m: m.ts)  # 오래된→최신(추이 차트용)
        return points

    # ---- catalog (S3 of latest run + DynamoDB overrides) ----
    def get_catalog(self, run_id: str | None = None) -> list[CatalogEntry]:
        rid = run_id or self.latest_run_id()
        if not rid:
            return []
        storage = self._storage(rid)
        if not storage.exists("catalog.json"):
            return []
        raw = storage.read_json("catalog.json")
        entries = [CatalogEntry.model_validate(e) for e in raw]  # type: ignore[union-attr]
        # DynamoDB catalog override(approve/PATCH 조정) 병합 — 사람이 바꾼 상태를 반영.
        overrides = self._catalog_overrides()
        for e in entries:
            ov = overrides.get(e.persona)
            if ov:
                # 승인은 **그 시점 멤버셋에 대한 승인**이다. approved 상속은 멤버셋 지문이
                # **존재하고(present) 현재와 일치할(match) 때만** 허용한다(fail-closed). 지문이 없거나
                # (레거시 override) 불일치하면 approved 를 상속하지 않고 draft 로 강등(재승인 요구).
                # approved 가 아닌 상태(draft/review 등)는 그대로 반영.
                if "approval_status" in ov:
                    ov_status = ov.get("approval_status")
                    if ov_status == "approved":
                        ov_hash = ov.get("member_hash")
                        cur_hash = _member_hash(e.members)
                        # 해시 present AND match 일 때만 approved. 그 외(없음/불일치) 전부 draft.
                        e.approval_status = "approved" if (ov_hash and ov_hash == cur_hash) else "draft"
                    else:
                        e.approval_status = ov_status
                if "actions" in ov and ov["actions"]:
                    e.actions = [PolicyAction.model_validate(a) for a in ov["actions"]]
        return entries

    def _catalog_overrides(self) -> dict[str, dict]:
        """도구 소유 DynamoDB catalog 테이블의 persona별 조정 override."""
        if not self.s.catalog_table:
            return {}
        try:
            items = self._scan(self.s.catalog_table)
        except Exception:  # noqa: BLE001 — 테이블 비었거나 접근 불가면 override 없음
            return {}
        return {i["persona"]: _from_ddb(i) for i in items if "persona" in i}

    def put_catalog_override(self, persona: str, fields: dict, *, expected_version: int | None = None) -> int:
        """persona 조정 저장(approve/PATCH) — 속성 병합 + 낙관적 락.

        과거엔 `put_item`(전체 교체)이라 동시 요청이 서로의 속성을 지웠다(approve 가 actions 를,
        PATCH 가 approval_status 를 덮음). 이제 `update_item`(SET 병합) + `version` 속성 +
        `ConditionExpression` 으로 원자적 병합한다. 버전 불일치(동시 쓰기)면 CatalogConflict(→409).

        expected_version=None 이면 현재 version 을 읽어 그 위에 +1(read-modify-write 낙관적 락).
        반환: 갱신된 version. 도구 소유 DynamoDB catalog 만(멤버계정 무관).
        """
        from boto3.dynamodb.conditions import Attr
        from botocore.exceptions import ClientError

        table = self._ddb.Table(self.s.catalog_table)
        if expected_version is None:
            existing = table.get_item(Key={"persona": persona}).get("Item") or {}
            expected_version = int(existing.get("version", 0))
        new_version = expected_version + 1

        ddb_fields = _to_ddb_item(fields)
        # SET 절 구성 — 넘어온 속성만 병합(나머지 기존 속성 보존).
        set_parts = ["#v = :newv"]
        names: dict[str, str] = {"#v": "version"}
        values: dict[str, Any] = {":newv": new_version}
        for i, (k, val) in enumerate(ddb_fields.items()):
            set_parts.append(f"#f{i} = :f{i}")
            names[f"#f{i}"] = k
            values[f":f{i}"] = val
        update_expr = "SET " + ", ".join(set_parts)
        # 조건: 항목이 없거나(version 없음) version 이 기대값과 일치할 때만.
        cond = Attr("version").not_exists() | Attr("version").eq(expected_version)
        try:
            table.update_item(
                Key={"persona": persona},
                UpdateExpression=update_expr,
                ConditionExpression=cond,
                ExpressionAttributeNames=names,
                ExpressionAttributeValues=values,
            )
        except ClientError as e:
            if e.response.get("Error", {}).get("Code") == "ConditionalCheckFailedException":
                raise CatalogConflict(persona) from e
            raise
        return new_version

    def get_policy_doc(self, persona: str, run_id: str | None = None) -> dict | None:
        """persona 정책 문서. 승인 시 저장된 **편집본 override 를 우선** 반환한다
        (승인=집행 일치 — provision-ps 가 읽는 문서와 승인본을 같게). 없으면 S3 합성 정책."""
        overrides = self._catalog_overrides()
        ov = overrides.get(persona)
        if ov and isinstance(ov.get("policy_doc"), dict) and ov["policy_doc"]:
            return ov["policy_doc"]
        rid = run_id or self.latest_run_id()
        if not rid:
            return None
        storage = self._storage(rid)
        key = f"policies/{persona}.json"
        return storage.read_json(key) if storage.exists(key) else None  # type: ignore[return-value]

    # ---- cleanup backlog (S3 csv of latest run) ----
    def get_cleanup(self, run_id: str | None = None) -> list[CleanupItem]:
        import csv
        import io

        rid = run_id or self.latest_run_id()
        if not rid:
            return []
        storage = self._storage(rid)
        if not storage.exists("cleanup_backlog.csv"):
            return []
        text = storage.read_bytes("cleanup_backlog.csv").decode("utf-8")
        reader = csv.DictReader(io.StringIO(text))
        return [CleanupItem.model_validate(_cleanup_row(row)) for row in reader]

    # ---- accounts (collection_manifest of latest run) ----
    def list_accounts(self, run_id: str | None = None) -> list[dict]:
        """최신 run 의 collection_manifest 에서 수집된 계정 목록·상태를 반환.

        각 dict: {account_id, status, is_tooling}. 관제(호출자) 계정은 is_tooling=True.
        manifest 없거나 단일계정(self)이면 그 계정 1건. 계정 선택기·필터의 소스.
        """
        rid = run_id or self.latest_run_id()
        if not rid:
            return []
        storage = self._storage(rid)
        if not storage.exists("collection_manifest.json"):
            return []
        manifest = storage.read_json("collection_manifest.json")
        if not isinstance(manifest, dict):
            return []
        accounts = manifest.get("accounts", [])
        # 관제 계정 판별: cross_account=false 면 유일 계정이 관제. cross_account 면 config 로는 알 수
        # 없으므로(멤버도 assume) manifest 만으로는 구분 불가 → 첫 계정을 관제로 보지 않고 별도 표기 없음.
        # 대신 tooling 계정 ID 를 env(LP2PS_TOOLING_ACCOUNT)로 받으면 표기.
        import os

        tooling = os.environ.get("LP2PS_TOOLING_ACCOUNT", "")
        out: list[dict] = []
        for a in accounts:
            aid = a.get("account_id", "")
            # 계정 수집 상태 = 소스 상태의 최악(하나라도 degraded/skipped면 그걸로).
            statuses = [s.get("status", "") for s in a.get("sources", [])]
            status = "ok"
            if "degraded" in statuses:
                status = "degraded"
            elif statuses and all(s == "skipped" for s in statuses):
                status = "skipped"
            out.append({"account_id": aid, "status": status, "is_tooling": aid == tooling})
        return sorted(out, key=lambda x: x["account_id"])

    # ---- run manifest (source-level status of a run) ----
    def get_run_manifest(self, run_id: str) -> dict | None:
        """한 run 의 collection_manifest 를 UI 실행 이력 상세용으로 반환.

        반환: {run_id, status, status_summary, accounts:[{account_id, sources:[{source,status,note}]}]}
        (없으면 None). '왜 degraded/부분 상태인지' 근거(소스별 status·note)를 그대로 노출한다.
        """
        storage = self._storage(run_id)
        if not storage.exists("collection_manifest.json"):
            return None
        manifest = storage.read_json("collection_manifest.json")
        if not isinstance(manifest, dict):
            return None
        # skipped 만인 옛 산출물엔 status_summary 가 없을 수 있어 여기서 파생(하위호환).
        summary = manifest.get("status_summary")
        accounts = manifest.get("accounts", [])
        if summary is None:
            all_sources = [s for a in accounts for s in a.get("sources", [])]
            summary = {
                "degraded_sources": sorted({s["source"] for s in all_sources if s.get("status") == "degraded"}),
                "skipped_sources": sorted({s["source"] for s in all_sources if s.get("status") == "skipped"}),
                "has_skipped": any(s.get("status") == "skipped" for s in all_sources),
            }
        return {
            "run_id": manifest.get("run_id", run_id),
            "status": manifest.get("status", "succeeded"),
            "status_summary": summary,
            "accounts": [
                {
                    "account_id": a.get("account_id", ""),
                    "sources": [
                        {"source": s.get("source", ""), "status": s.get("status", ""), "note": s.get("note", "")}
                        for s in a.get("sources", [])
                    ],
                }
                for a in accounts
            ],
        }

    # ---- presigned URLs (S3) ----
    def presign(self, run_id: str, relpath: str, expires: int = 900, *, claims: dict | None = None) -> str:
        # S3Storage 와 **동일한 키 계산**을 재사용(경로 소스 단일화). 직접 문자열 조합하면
        # base prefix 가 붙은 버킷 URI 에서 storage 와 어긋나 404 가 난다.
        from .audit import audit_event

        storage = self._storage(run_id)
        key = storage._key(relpath)  # noqa: SLF001 — 같은 계층(repositories)에서 키 규칙 재사용
        params: dict[str, Any] = {"Bucket": self.s.data_bucket, "Key": key}
        # NOTE: ExpectedBucketOwner 는 presigned URL 에 **넣지 않는다**. presign 에 넣으면
        # x-amz-expected-bucket-owner 가 SigV4 SignedHeaders 에 포함되는데(쿼리스트링 서명),
        # 브라우저는 URL 을 열 때 이 헤더를 보낼 수 없어 S3 가 SignatureDoesNotMatch(403, XML)
        # 를 반환한다("This XML file..."). presign 은 서버가 Bucket/Key 를 고정해 서명하므로
        # 클라이언트가 버킷을 재바인딩할 여지가 없어 EBO 의 confused-deputy 방어 가치가 없다.
        # 서버측 직접 read/write(storage.py)의 ExpectedBucketOwner 는 그대로 유지한다.
        # 민감 데이터(리포트/IaC) 접근 감사.
        audit_event(action="presign", resource=f"{run_id}/{relpath}", result="success", claims=claims)
        return self._s3.generate_presigned_url("get_object", Params=params, ExpiresIn=expires)

    def run_artifact_exists(self, run_id: str, relpath: str) -> bool:
        return self._storage(run_id).exists(relpath)

    # ---- helpers ----
    def _storage(self, run_id: str) -> S3Storage:
        return S3Storage(f"s3://{self.s.data_bucket}", self.s.customer, run_id)

    # 무제한 scan/응답 크기 상한. 단일테넌트·운영자 소유 데이터라 실위험은 낮으나,
    # 페이지 상한(_SCAN_MAX_PAGES)·항목 상한(_SCAN_MAX_ITEMS)으로 폭주(메모리/지연/응답크기)를 막는다.
    _SCAN_MAX_PAGES = 50
    _SCAN_MAX_ITEMS = 5000

    def _scan(self, table_name: str) -> list[dict]:
        import logging

        table = self._ddb.Table(table_name)
        items: list[dict] = []
        resp = table.scan()
        items.extend(resp.get("Items", []))
        pages = 1
        while "LastEvaluatedKey" in resp and pages < self._SCAN_MAX_PAGES and len(items) < self._SCAN_MAX_ITEMS:
            resp = table.scan(ExclusiveStartKey=resp["LastEvaluatedKey"])
            items.extend(resp.get("Items", []))
            pages += 1
        if "LastEvaluatedKey" in resp and (pages >= self._SCAN_MAX_PAGES or len(items) >= self._SCAN_MAX_ITEMS):
            # 상한 도달로 잘렸음을 로그로 남긴다(조용한 truncation 금지).
            logging.getLogger("lp2ps.api").warning(
                "scan 상한 도달(table=%s, pages=%d, items=%d) — 결과가 잘렸습니다.",
                table_name, pages, len(items),
            )
        return items[: self._SCAN_MAX_ITEMS]


def _cleanup_row(row: dict[str, Any]) -> dict[str, Any]:
    """cleanup_backlog.csv 한 행 → CleanupItem 검증용 dict.

    risk_reasons 는 엔진이 '|' 로 join 한 문자열 → 리스트 복원. evidence 는 JSON 문자열 → dict.
    구버전 CSV(컬럼 없음)도 안전(기본값 0/[]/{}). risk_score 는 pydantic 이 str→int 강제.
    """
    import json

    out = dict(row)
    reasons = out.get("risk_reasons")
    out["risk_reasons"] = reasons.split("|") if reasons else []
    if not out.get("risk_score"):
        out["risk_score"] = 0
    ev = out.get("evidence")
    try:
        out["evidence"] = json.loads(ev) if ev else {}
    except (ValueError, TypeError):
        out["evidence"] = {}
    return out


def _from_ddb(item: dict[str, Any]) -> dict[str, Any]:
    """DynamoDB Item(Decimal 포함) → pydantic 검증 가능한 dict(Decimal→int/float)."""
    from decimal import Decimal

    def _conv(v: Any) -> Any:
        if isinstance(v, Decimal):
            return int(v) if v % 1 == 0 else float(v)
        if isinstance(v, dict):
            return {k: _conv(x) for k, x in v.items()}
        if isinstance(v, list):
            return [_conv(x) for x in v]
        return v

    return {k: _conv(v) for k, v in item.items()}


def _to_ddb_item(obj: dict[str, Any]) -> dict[str, Any]:
    """DynamoDB put_item 용 — float→Decimal(DynamoDB 는 float 미지원), 빈 문자열 제거."""
    import json
    from decimal import Decimal

    return json.loads(json.dumps(obj), parse_float=Decimal)
