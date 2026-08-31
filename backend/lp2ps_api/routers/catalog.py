"""catalog 라우터 — GET/PATCH/approve/terraform/provision-ps.

- GET /catalog: persona 카탈로그(최신 run S3).
- PATCH /catalog/{persona}: 조정(도구 DynamoDB catalog 만, draft) — action include 토글 등.
- POST /catalog/{persona}/approve: approved 전이 + persona Permission Set Terraform 생성·반환.
- GET /catalog/{persona}/terraform: 승인된 persona 의 .tf(다운로드).
- POST /catalog/{persona}/provision-ps: 승인된 persona 를 tooling-IdC 에 PS 정의 생성(UI 2차+최종
  확인 후). account assignment 은 절대 안 함(불변식① — 멤버계정 권한 부여는 사람 수동). IdC 인스턴스
  ARN 은 런타임 자동 조회, IdC 전용 클라이언트로만 쓰기.

쓰기 경계: PATCH/approve 는 도구 소유 DynamoDB catalog 만. provision-ps 만 유일한 외부 write
(sso-admin, 전용 경로). 멤버계정 IAM write 는 어디에도 없음.
"""

from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException
from pydantic import BaseModel

from lp2ps.models import (
    CatalogEntry,
    PolicyAction,
    PolicyArtifact,
    ProvisionResult,
    TerraformArtifact,
)
from lp2ps.policy_export import build_artifacts, iam_name, permission_set_artifact

from ..audit import audit_event
from ..auth import require_auth
from ..customer_config import config_inline, uses_identity_center
from ..deps import get_settings, valid_persona
from ..repositories import CatalogConflict
from . import get_repos

router = APIRouter(tags=["catalog"])


class PatchPersonaRequest(BaseModel):
    """PATCH /catalog/{persona} 본문 — 경계에서 타입 검증(실패 시 422). 알 수 없는 필드는 거부."""

    model_config = {"extra": "forbid"}
    actions: list[PolicyAction] = []


@router.get("/catalog")
def get_catalog() -> list[CatalogEntry]:
    return get_repos().get_catalog()


@router.get("/catalog/{persona}/terraform")
def get_terraform(persona: str) -> TerraformArtifact:
    _check_persona(persona)
    entry = _find_persona(persona)
    policy_doc = get_repos().get_policy_doc(persona)
    if policy_doc is None:
        raise HTTPException(status_code=404, detail=f"persona 정책 없음: {persona}")
    return _to_terraform(entry, policy_doc)


@router.get("/catalog/{persona}/artifacts")
def get_artifacts(persona: str) -> list[PolicyArtifact]:
    """persona 정책의 **반영 산출물** 목록(IAM 정책/역할 .tf, 정책 JSON, 그리고 IdC 면 PS .tf).

    IdC 를 쓰지 않는 고객이 승인된 정책을 실제로 반영할 수 있게 하는 경로다 — PS 산출물만 있던
    시절엔 정책을 다듬어 승인해도 apply 할 물건이 없었다. 포함 여부는
    `provisioning.uses_identity_center`(config)가 가른다.
    """
    _check_persona(persona)
    entry = _find_persona(persona)
    policy_doc = get_repos().get_policy_doc(persona)
    if policy_doc is None:
        raise HTTPException(status_code=404, detail=f"persona 정책 없음: {persona}")
    return _to_artifacts(entry, policy_doc)


@router.patch("/catalog/{persona}")
def patch_persona(persona: str, req: PatchPersonaRequest, claims: dict = Depends(require_auth)) -> CatalogEntry:
    """persona 조정(정책 편집기 action include 토글 등) — 도구 DynamoDB catalog override 에 저장.

    본문은 PatchPersonaRequest 로 **경계에서 검증**(잘못된 형식 → 422). 검증 성공 후에만
    저장한다(과거엔 저장→검증 순서라 잘못된 입력에도 부분 저장되는 버그가 있었음). draft 상태 유지.
    다음 GET /catalog 이 이 override 를 병합해 반환한다. 멤버계정 무관.
    """
    _check_persona(persona)
    entry = _find_persona(persona)
    if req.actions:
        # 이미 PolicyAction 으로 검증된 값 — dict 로 직렬화해 저장(검증 통과 후 저장).
        actions_dump = [a.model_dump() for a in req.actions]
        try:
            get_repos().put_catalog_override(persona, {"actions": actions_dump})
        except CatalogConflict as e:
            raise HTTPException(status_code=409, detail="동시 수정 충돌 — 새로고침 후 다시 시도하세요.") from e
        audit_event(action="catalog_override", resource=persona, result="success", claims=claims)
        entry = entry.model_copy(update={"actions": req.actions})
    return entry


@router.post("/catalog/{persona}/approve")
def approve_persona(
    persona: str,
    policy_doc: str = Body(default="", embed=True),
    claims: dict = Depends(require_auth),
) -> dict:
    """승인 → approved 전이(**도구 DynamoDB catalog 에 persist**) + Terraform 반환.

    전달된 편집본 policy_doc 를 override 에 **함께 저장**한다(승인=집행 일치 — provision-ps 가
    읽는 정책과 승인본을 같게). 과거엔 approval_status 만 저장해 편집 정책이 유실됐다.
    승인은 그 시점 멤버셋에 대한 것이므로 member_hash 를 함께 저장한다(멤버 바뀌면 재승인).
    멤버계정 무관.
    """
    from ..repositories import _member_hash

    _check_persona(persona)
    entry = _find_persona(persona)
    approved = entry.model_copy(update={"approval_status": "approved"})

    parsed = _parse_policy(policy_doc)
    # approved 상태 + 멤버셋 지문 + (있으면) 편집 정책본을 원자적으로 기록.
    override: dict = {"approval_status": "approved", "member_hash": _member_hash(entry.members)}
    if parsed is not None:
        override["policy_doc"] = parsed
    try:
        get_repos().put_catalog_override(persona, override)
    except CatalogConflict as e:
        raise HTTPException(status_code=409, detail="동시 수정 충돌 — 새로고침 후 다시 시도하세요.") from e
    audit_event(action="approve_persona", resource=persona, result="approved", claims=claims)

    # 편집된 정책 문서가 오면 그걸로, 아니면 저장된 합성 정책으로 산출물 생성.
    doc = parsed or get_repos().get_policy_doc(persona) or _empty_policy()
    tf = _to_terraform(approved, doc)
    # artifacts = 반영 산출물 전체(IAM 정책/역할/JSON + IdC 면 PS). terraform 은 기존 계약이라
    # 유지한다(PS 를 쓰는 고객의 provision-ps 흐름이 이 필드를 참조).
    artifacts = _to_artifacts(approved, doc)
    return {
        "entry": approved.model_dump(),
        "terraform": tf.model_dump(),
        "artifacts": [a.model_dump() for a in artifacts],
    }


@router.post("/catalog/{persona}/provision-ps")
def provision_ps(persona: str, claims: dict = Depends(require_auth)) -> ProvisionResult:
    """승인된 persona 를 tooling-IdC 에 Permission Set **정의**로 생성한다.

    안전 가드(불변식①): (i) UI 2차+최종 확인 후 호출, (ii) approved 상태만, (iii) account assignment 은
    절대 하지 않음(assignment_skipped=True — 멤버계정 권한 부여는 사람 수동), (iv) tooling-IdC 전용
    클라이언트로만 쓰기(멤버계정 read-only 훅 불변). IdC 인스턴스 ARN 은 런타임 자동 조회.
    """
    _check_persona(persona)

    # 승인된 persona 만 provision(2차 확인 워크플로 — draft/review 는 거부).
    entry = _find_persona(persona)
    if entry.approval_status != "approved":
        raise HTTPException(
            status_code=409,
            detail=f"persona 가 approved 상태가 아님({entry.approval_status}). 먼저 승인하세요.",
        )
    policy_doc = get_repos().get_policy_doc(persona) or _empty_policy()
    inline = {k: v for k, v in policy_doc.items() if not k.startswith("_")}

    import json

    import boto3

    from lp2ps.provisioning import provision_permission_set

    # IdC 리전(계정당 단일 리전, config.region 과 다를 수 있음). config 에 있으면 사용, 없으면 자동 조회.
    idc_region = _idc_region()
    session = boto3.Session()
    instance_arn = _resolve_idc_instance_arn(session, idc_region)
    if not instance_arn:
        raise HTTPException(status_code=409, detail=f"IdC 인스턴스를 찾지 못함(region={idc_region}).")

    from lp2ps.runctx import new_run_context

    now = new_run_context("provision").started_at  # 감사용 타임스탬프(ISO8601)
    try:
        result = provision_permission_set(
            session=session,
            instance_arn=instance_arn,
            persona=entry.persona,
            inline_policy_json=json.dumps(inline, sort_keys=True, ensure_ascii=False),
            provisioned_at=now,
            region=idc_region,  # IdC 쓰기는 IdC 리전으로.
        )
    except Exception as e:  # noqa: BLE001 — IdC 오류를 502 로 노출(멤버계정 무관)
        # IdC write 실패 감사.
        audit_event(action="provision_ps", resource=persona, result="failure", claims=claims,
                    error_type=type(e).__name__)
        raise HTTPException(status_code=502, detail=f"IdC PS 정의 생성 실패: {type(e).__name__}") from e
    # IdC write 성공 감사(가장 민감한 외부 쓰기).
    audit_event(action="provision_ps", resource=persona, result="success", claims=claims,
                assignment_skipped=result.assignment_skipped)
    return result


def _config_inline() -> dict:
    """고객 config(JSON) — 정본은 `..customer_config.config_inline`(여러 라우터가 공유)."""
    return config_inline()


def _idc_region() -> str:
    """provisioning.idc_region(config) → 없으면 API 리전. IdC 는 계정당 단일 리전."""
    import os

    r = _config_inline().get("provisioning", {}).get("idc_region")
    if r:
        return r
    return os.environ.get("AWS_REGION", "us-west-2")


def _uses_identity_center() -> bool:
    """이 고객이 IdC 를 쓰는가 — 정본은 `..customer_config.uses_identity_center`."""
    return uses_identity_center()


def _session_duration(persona: str) -> str:
    """PS 세션 유지시간(config permission_sets). 엔진 M7 과 같은 규칙(persona 개별 override 우선)."""
    ps_cfg = _config_inline().get("permission_sets", {})
    overrides = ps_cfg.get("session_duration_overrides") or {}
    return overrides.get(persona) or ps_cfg.get("session_duration") or "PT8H"


def _resolve_idc_instance_arn(session, idc_region: str) -> str | None:  # noqa: ANN001
    """tooling 계정 IdC 인스턴스 ARN 자동 조회(sso-admin:ListInstances). 첫 인스턴스(ARN 정렬)."""
    from lp2ps.provisioning import unguarded_idc_client

    sso = unguarded_idc_client(session, "sso-admin", region_name=idc_region)
    arns = sorted(i["InstanceArn"] for i in sso.list_instances().get("Instances", []))
    return arns[0] if arns else None


# ---- helpers ----
def _check_persona(persona: str) -> None:
    if not valid_persona(persona):
        raise HTTPException(status_code=400, detail="잘못된 persona 형식")


def _find_persona(persona: str) -> CatalogEntry:
    for e in get_repos().get_catalog():
        if e.persona == persona:
            return e
    raise HTTPException(status_code=404, detail=f"persona 없음: {persona}")


def _to_artifacts(entry: CatalogEntry, policy_doc: dict) -> list[PolicyArtifact]:
    """persona + 정책 문서 → 반영 산출물 목록. 생성은 엔진 `policy_export` 단일 소스."""
    return build_artifacts(
        entry.persona,
        entry.description,
        policy_doc,
        uses_identity_center=_uses_identity_center(),
        session_duration=_session_duration(entry.persona),
    )


def _to_terraform(entry: CatalogEntry, policy_doc: dict) -> TerraformArtifact:
    """persona + 정책 문서 → Permission Set Terraform(HCL).

    HCL 본문은 엔진 `policy_export` 가 만든다 — 예전엔 이 함수·M7 템플릿·프론트 mock 이 각자
    HCL 을 조립해 세 곳이 조용히 달라질 수 있었다(세션 유지시간이 실제로 달랐다: 여기 PT8H 고정,
    M7 은 config 값). IdC 미사용 고객이어도 이 엔드포인트는 PS 형태를 그대로 반환한다 — 기존 계약이고,
    산출물 선택은 `/artifacts` 가 담당한다.
    """
    art = permission_set_artifact(
        entry.persona, entry.description, policy_doc,
        session_duration=_session_duration(entry.persona),
    )
    return TerraformArtifact(
        persona=entry.persona,
        permission_set_name=iam_name(entry.persona),
        filename=art.filename,
        hcl=art.content,
    )


def _parse_policy(policy_doc: str) -> dict | None:
    """편집본 policy_doc 파싱.

   (1차 후속): 빈 문자열(편집 안 함)만 None 으로 허용한다. **비어있지 않은데 JSON
    파싱 실패거나 객체(dict)가 아니면 조용히 버리지 않고 422** 로 거부한다(승인=집행 일치이므로
    잘못된 편집본을 무시하고 다른 정책을 집행하면 안 됨).
    """
    import json

    if not policy_doc.strip():
        return None  # 편집 안 함 — 저장된 합성 정책 사용
    try:
        parsed = json.loads(policy_doc)
    except (ValueError, TypeError) as e:
        raise HTTPException(status_code=422, detail="policy_doc 가 올바른 JSON 이 아닙니다.") from e
    if not isinstance(parsed, dict):
        raise HTTPException(status_code=422, detail="policy_doc 는 JSON 객체(정책 문서)여야 합니다.")
    return parsed


def _empty_policy() -> dict:
    return {"Version": "2012-10-17", "Statement": []}
