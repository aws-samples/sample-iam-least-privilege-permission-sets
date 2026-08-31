"""M7 IaC Emitter — policies + permission_sets → Terraform HCL.

catalog + 합성된 policies/<persona>.json 을 렌더해 다음을 만든다:
- `iac/iam_policies.tf`        — persona 별 관리형 IAM 정책(**항상**). IdC 를 쓰지 않는 고객이
                                 실제로 반영할 수 있는 유일한 산출물이다. 생성은 `policy_export`
                                 (백엔드 개별 다운로드와 같은 코드 — 화면과 파일이 어긋나지 않게).
- `iac/permission_sets.tf`     — persona 별 Permission Set 정의 + inline policy(최소권한).
                                 `provisioning.uses_identity_center=false` 면 내지 않는다.
- `iac/account_assignments.tf` — **주석 골격만**(불변식 ①: account assignment 은 도구가 안 함, 사람 수동)
- `iac/providers.tf`           — provider + IdC instance ARN 변수

불변식 ②(결정론): persona 정렬·안정 JSON 직렬화 → 같은 입력 → 같은 HCL. 템플릿 렌더도 순수.
불변식 ①: AWS 미호출(도구 소유 출력만 기록).
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from jinja2 import Environment, PackageLoader, StrictUndefined

from .models import CatalogEntry
from .policy_export import build_bulk_iam_policies

if TYPE_CHECKING:  # pragma: no cover
    from .config import Config
    from .runctx import RunContext
    from .storage import Storage

IAC_DIR = "iac"

# autoescape=False 는 의도적이다: 출력은 HTML 이 아니라 Terraform HCL 이라 HTML 이스케이프는
# 오히려 HCL 을 깨뜨린다. XSS 위험은 없으며(HTML 아님), HCL 문자열 탈출 방지는 값 주입 단계에서
# 처리한다 — persona 명/리소스명은 영숫자로 정제(_tf_name), description 은 따옴표 제거,
# inline_policy 는 json.dumps 로 인코딩. 신뢰 경계: 입력은 도구가 생성한 catalog(사용자 자유입력 아님).
_env = Environment(  # nosec B701 — HCL 출력(HTML 아님), 값은 주입 시 정제/JSON 인코딩
    loader=PackageLoader("lp2ps", "iac_templates"),
    autoescape=False,
    undefined=StrictUndefined,
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
)


def emit_iac(storage: "Storage", run: "RunContext", cfg: "Config") -> dict[str, str]:
    """catalog + policies → iac/*.tf. 반환 = {상대경로: 렌더된 HCL}."""
    catalog = sorted(_load_catalog(storage), key=lambda e: e.persona)  # 결정론(입력 순서에 의존 금지)
    # 정책은 persona 당 한 번만 읽는다(PS·IAM 산출물이 같은 문서를 쓴다).
    policies = {entry.persona: _load_policy(storage, entry) for entry in catalog}
    ps_models = [_ps_model(entry, policies[entry.persona], cfg) for entry in catalog]
    # included action 이 0 이라 정책 Statement 가 비는 persona 는 PS 를 생성하지 않는다
    # (빈 inline policy 는 apply 시 IAM 이 거부 — 최소 1 Statement 필요).
    ps_models = [p for p in ps_models if p["has_statements"]]
    ps_models.sort(key=lambda p: p["resource_name"])  # 결정론 순서

    outputs: dict[str, str] = {}
    outputs[f"{IAC_DIR}/providers.tf"] = _env.get_template("providers.tf.j2").render(
        region=cfg.region,
        # Terraform var 기본값 — 사용자가 tfvars 로 채운다(런타임 provision-ps 는 자동 조회 사용).
        identity_center_instance_arn="",
    )

    # IdC 를 쓰지 않는 고객용 산출물 — 관리형 IAM 정책. **항상 낸다**(IdC 고객도 IdC 밖 역할에
    # 같은 정책을 붙일 수 있다). 이게 없으면 non-IdC 고객은 run 산출물에서 쓸 게 하나도 없다.
    outputs[f"{IAC_DIR}/iam_policies.tf"] = build_bulk_iam_policies(
        [(entry.persona, policies[entry.persona]) for entry in catalog]
    )

    # PS 산출물은 IdC 를 쓰는 고객에게만. IdC 인스턴스가 없으면 apply 자체가 불가능해
    # `var.identity_center_instance_arn` 만 물어보는 쓸모없는 파일이 된다.
    if cfg.provisioning.uses_identity_center:
        outputs[f"{IAC_DIR}/permission_sets.tf"] = _env.get_template("permission_sets.tf.j2").render(
            permission_sets=ps_models
        )
        outputs[f"{IAC_DIR}/account_assignments.tf"] = _env.get_template(
            "account_assignments.tf.j2"
        ).render(permission_sets=ps_models)

    for relpath, content in outputs.items():
        storage.write_text(relpath, content)
    return outputs


def _ps_model(entry: CatalogEntry, policy_doc: dict, cfg: "Config") -> dict:
    """CatalogEntry + 합성 정책 → 템플릿용 dict."""
    # inline policy 는 표준 IAM 문서만(메타 _lp2ps 제거).
    inline = {k: v for k, v in policy_doc.items() if not k.startswith("_")}
    session_duration = cfg.permission_sets.session_duration_overrides.get(
        entry.persona, cfg.permission_sets.session_duration
    )
    return {
        "persona": entry.persona,
        "resource_name": _tf_name(entry.persona),
        "name": entry.persona,
        # HCL 문자열 탈출 방지: 따옴표·개행·백슬래시 제거(설명은 도구 생성이나 방어적으로).
        "description": entry.description.replace("\\", " ").replace('"', "'").replace("\n", " ").replace("\r", " ")[:200],
        "session_duration": session_duration,
        "synthesis_source": entry.synthesis_source,
        "member_count": entry.member_count,
        # jinja 에서 jsonencode(...) 안에 들어갈 결정론 JSON 문자열.
        "inline_policy": json.dumps(inline, sort_keys=True, ensure_ascii=False),
        "has_statements": bool(inline.get("Statement")),
    }


def _tf_name(persona: str) -> str:
    """Terraform 리소스 로컬명(영숫자·밑줄, 소문자)."""
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in persona).strip("_").lower()
    return cleaned or "persona"


def _load_catalog(storage: "Storage") -> list[CatalogEntry]:
    raw = storage.read_json("catalog.json")
    return [CatalogEntry.model_validate(e) for e in raw]  # type: ignore[union-attr]


def _load_policy(storage: "Storage", entry: CatalogEntry) -> dict:
    key = f"policies/{entry.persona}.json"
    if not storage.exists(key):
        return {"Version": "2012-10-17", "Statement": []}
    return storage.read_json(key)  # type: ignore[return-value]
