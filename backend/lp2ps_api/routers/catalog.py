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

from lp2ps.models import CatalogEntry, PolicyAction, ProvisionResult, TerraformArtifact

from ..audit import audit_event
from ..auth import require_auth
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

    # 편집된 정책 문서가 오면 그걸로, 아니면 저장된 합성 정책으로 Terraform 생성.
    doc = parsed or get_repos().get_policy_doc(persona) or _empty_policy()
    tf = _to_terraform(approved, doc)
    return {"entry": approved.model_dump(), "terraform": tf.model_dump()}


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


def _idc_region() -> str:
    """provisioning.idc_region(config) → 없으면 API 리전. IdC 는 계정당 단일 리전."""
    import json
    import os

    inline = os.environ.get("LP2PS_CONFIG_INLINE")
    if inline:
        r = json.loads(inline).get("provisioning", {}).get("idc_region")
        if r:
            return r
    return os.environ.get("AWS_REGION", "us-west-2")


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


def _to_terraform(entry: CatalogEntry, policy_doc: dict) -> TerraformArtifact:
    """persona + 정책 문서 → Permission Set Terraform(HCL). 엔진 m7_iac_emitter 와 동일 형태."""
    import json

    inline = {k: v for k, v in policy_doc.items() if not k.startswith("_")}
    res = "".join(ch if ch.isalnum() else "_" for ch in entry.persona).strip("_").lower() or "persona"
    ps_name = f"{entry.persona}-least-privilege"
    hcl = f"""# 자동 생성 — LP2PS. 검토 후 apply 하세요.
resource "aws_ssoadmin_permission_set" "{res}" {{
  name             = "{ps_name}"
  description      = "LP2PS 최소권한 — {entry.persona}"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "PT8H"
}}

resource "aws_ssoadmin_permission_set_inline_policy" "{res}" {{
  instance_arn       = var.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.{res}.arn
  inline_policy      = jsonencode({json.dumps(inline, sort_keys=True, ensure_ascii=False)})
}}

# account assignment 은 의도적으로 생성하지 않음 — 필요 시 사람이 수동으로 추가.
"""
    return TerraformArtifact(
        persona=entry.persona, permission_set_name=ps_name,
        filename=f"{entry.persona}.tf", hcl=hcl,
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
