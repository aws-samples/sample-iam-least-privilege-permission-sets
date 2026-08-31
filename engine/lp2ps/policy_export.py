"""승인된 persona 정책 → 반영 산출물(IAM 정책/역할 Terraform, 정책 JSON, IdC Permission Set).

**왜 필요한가**: 기존 산출물은 `aws_ssoadmin_permission_set` 하나뿐이었다. IdC(Identity Center)를
쓰지 않는 고객은 그 `.tf` 를 apply 할 IdC 인스턴스가 없어서, 정책을 다듬고 승인해도 **반영할 물건이
없었다**. 여기서 IAM 관리형 정책·역할 산출물을 함께 만든다.

**왜 별 모듈인가**: 같은 HCL 을 세 곳이 만들고 있었다(M7 jinja 템플릿, 백엔드 `_to_terraform`,
프론트 mock). 드리프트가 생기면 "화면에서 본 것"과 "다운로드한 것"이 달라진다. 단일 소스로 모은다.

**왜 jinja 를 안 쓰는가**: 이 모듈은 API Lambda(백엔드)도 import 한다. M7 처럼 jinja2 를 쓰면 API
번들에 jinja2 와 패키지 템플릿 데이터가 있어야 하고, 없으면 import 시점에 죽는다. 순수 문자열 조립은
의존성이 없고 바이트 단위로 테스트하기도 쉽다.

불변식 ①: AWS 미호출(문자열 생성만). 불변식 ②(결정론): 정렬된 JSON 직렬화만 쓰고 wall-clock 없음
→ 같은 입력이면 바이트 동일. 불변식 ④: 계정ID·ARN 리터럴 없음 — 신뢰정책 주체는 Terraform 변수로 뺀다.
"""

from __future__ import annotations

import json

from .models import PolicyArtifact

# 산출물 공통 주의사항. 파일 주석에도 넣지만 UI 에도 그대로 노출한다 — 파일을 열지 않고 다운로드만
# 하는 경로가 있어서, 파일 안에만 적어두면 아무도 안 읽는다.
COMMON_NOTES = [
    "정책의 Resource 는 \"*\" 입니다 — action 만 최소화했고 리소스 범위는 좁히지 않았습니다. "
    "운영 반영 전에 리소스 조건을 좁히는 것을 권장합니다.",
    "이 정책은 이 persona 멤버 **전원의 관측된 실사용 action 합집합**입니다 — 개별 멤버에게는 필요 "
    "이상일 수 있습니다.",
    # 종전 문구는 "부족하지는 않습니다" 라고 **보장**했다. 근거가 없다: 합집합은 관측 창 안에서
    # 수집된 것뿐이고, CloudTrail LookupEvents 는 관리 이벤트만·페이지 상한이 있으며(요청한 창보다
    # 짧게 덮인다), 데이터 이벤트는 기본 미기록, Access Advisor 가 추적하지 않는 action 도 있다.
    # 이 문장을 지우면 apply 후 권한 부족 장애의 책임 소재가 도구 쪽으로 넘어온다.
    "**부족할 수 있습니다**: 관측 창(CloudTrail 페이지 상한·Access Advisor 추적 범위) 밖에서 쓴 "
    "action, 데이터 이벤트(S3 객체 접근 등 — 기본 미기록), 추적되지 않는 action 은 합집합에 없습니다. "
    "운영 반영 전 스테이징에서 검증하세요.",
    "다른 계정에 반영할 때는 계정마다 apply 하세요(provider alias 또는 Terraform workspace). "
    "LP2PS 는 계정 간 apply 를 수행하지 않습니다.",
]

_ROLE_NOTE = (
    "역할의 신뢰정책(누가 assume 하는가)은 LP2PS 가 알 수 없어 Terraform 변수로 비워뒀습니다. "
    "채우지 않고 apply 하면 아무도 사용할 수 없는 역할이 생깁니다."
)
_PS_NOTE = "account assignment(멤버계정 권한 부여)은 포함되지 않습니다 — 필요 시 사람이 수동으로 추가하세요."


def tf_name(persona: str) -> str:
    """Terraform 리소스 로컬명(영숫자·밑줄, 소문자). m7_iac_emitter._tf_name 과 동일 규칙."""
    cleaned = "".join(ch if ch.isalnum() else "_" for ch in persona).strip("_").lower()
    return cleaned or "persona"


def iam_name(persona: str) -> str:
    """IAM 정책·역할 이름. IAM 이름 허용 문자는 `[\\w+=,.@-]` 이므로 그 밖은 `-` 로 바꾼다."""
    allowed = set("+=,.@-_")
    cleaned = "".join(ch if (ch.isalnum() and ch.isascii()) or ch in allowed else "-" for ch in persona)
    return f"{cleaned.strip('-') or 'persona'}-least-privilege"[:128]


def _hcl_safe(text: str) -> str:
    """HCL 문자열 리터럴에 넣기 전 방어적 정제(따옴표·개행·백슬래시 제거). m7 과 동일 규칙."""
    return text.replace("\\", " ").replace('"', "'").replace("\n", " ").replace("\r", " ")[:200]


def _statement_doc(policy_doc: dict) -> dict:
    """표준 IAM 문서만 남긴다(`_lp2ps` 등 메타 키 제거)."""
    return {k: v for k, v in policy_doc.items() if not k.startswith("_")}


def _canonical_json(doc: dict) -> str:
    """결정론 JSON(키 정렬). HCL `jsonencode(...)` 인자로도 그대로 쓴다 — HCL2 객체 리터럴은
    `{"k": v}` 형태를 받으므로 json.dumps 출력이 유효한 HCL 표현식이다(M7 템플릿도 같은 방식)."""
    return json.dumps(doc, sort_keys=True, ensure_ascii=False)


def _header(persona: str, description: str, doc: dict, purpose: str) -> str:
    n_stmt = len(doc.get("Statement") or [])
    n_action = sum(len(_as_list(s.get("Action"))) for s in doc.get("Statement") or [])
    return (
        f"# 자동 생성 — LP2PS. 검토 후 apply 하세요.\n"
        f"#\n"
        f"# {purpose}\n"
        f"#\n"
        f"# persona: {persona}\n"
        f"# 설명: {_hcl_safe(description)}\n"
        f"# 정책: Statement {n_stmt}개 / action {n_action}개\n"
        f"#\n"
        f"# 주의: Statement 의 Resource 는 \"*\" 입니다 — action 만 최소화했고 리소스 범위는\n"
        f"#       좁히지 않았습니다. 이 정책은 persona 멤버 전원의 실사용 action 합집합입니다.\n"
        f"# 여러 계정에 반영: 계정마다 apply 하세요(provider alias 또는 workspace).\n"
    )


def _as_list(v: object) -> list:
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def policy_json_artifact(persona: str, policy_doc: dict) -> PolicyArtifact:
    """콘솔 붙여넣기·기존 정책 교체용 정책 문서 원문(사람이 읽는 들여쓰기)."""
    doc = _statement_doc(policy_doc)
    return PolicyArtifact(
        persona=persona,
        target="policy_json",
        label="정책 JSON",
        filename=f"{persona}.policy.json",
        content=json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        language="json",
        notes=list(COMMON_NOTES),
    )


def _iam_policy_block(persona: str, doc: dict) -> str:
    """`aws_iam_policy` 리소스 1개 + ARN output. 단일 persona 산출물과 M7 일괄 파일이 공유한다."""
    res = tf_name(persona)
    return f"""resource "aws_iam_policy" "{res}" {{
  name        = "{iam_name(persona)}"
  description = "LP2PS 최소권한 — {_hcl_safe(persona)}"
  policy      = jsonencode({_canonical_json(doc)})
}}

output "{res}_policy_arn" {{
  value       = aws_iam_policy.{res}.arn
  description = "생성된 관리형 정책 ARN — 기존 역할에 attach 할 때 사용하세요."
}}
"""


def iam_policy_artifact(persona: str, description: str, policy_doc: dict) -> PolicyArtifact:
    """관리형 IAM 정책 1개. **attach 하지 않는다** — 어느 역할·사용자에 붙일지는 사람이 정한다."""
    doc = _statement_doc(policy_doc)
    res = tf_name(persona)
    header = _header(
        persona, description, doc,
        "IdC(Identity Center)를 쓰지 않는 환경용. persona 최소권한을 관리형 IAM 정책 하나로 만듭니다.\n"
        "# 이 파일은 정책을 어디에도 attach 하지 않습니다 — 기존 역할·사용자에 사람이 붙이세요.",
    )
    hcl = header + "\n" + _iam_policy_block(persona, doc)
    return PolicyArtifact(
        persona=persona, target="iam_policy_tf", label="IAM 정책 (.tf)",
        filename=f"{persona}.iam-policy.tf", content=hcl, language="hcl",
        notes=list(COMMON_NOTES),
    )


def iam_role_artifact(persona: str, description: str, policy_doc: dict) -> PolicyArtifact:
    """역할까지 새로 만드는 경우.

    정책은 **inline**(`aws_iam_role_policy`)으로 붙인다 — 관리형(`aws_iam_policy`)으로 붙이면
    IAM 정책 산출물과 **같은 이름의 정책을 두 번 만들게 되어**(둘 다 apply 하면 EntityAlreadyExists)
    고객이 둘 중 하나를 못 쓴다. inline 이면 두 파일을 함께 apply 해도 충돌하지 않는다.
    """
    doc = _statement_doc(policy_doc)
    res = tf_name(persona)
    header = _header(
        persona, description, doc,
        "IdC 를 쓰지 않고 **역할까지 새로 만드는** 경우의 산출물.\n"
        "# 정책은 inline 으로 붙입니다. 관리형 정책으로 관리하려면 iam-policy.tf 를 쓰고 이 파일의\n"
        "# aws_iam_role_policy 블록을 지운 뒤 aws_iam_role_policy_attachment 로 붙이세요\n"
        "# (두 파일을 그대로 함께 apply 해도 리소스 충돌은 없습니다).",
    )
    hcl = f"""{header}
variable "{res}_trusted_principals" {{
  description = "이 역할을 assume 할 주체 ARN 목록. LP2PS 는 이 값을 정하지 않습니다 — 반드시 채우세요."
  type        = list(string)
  # 예: ["arn:aws:iam::<계정ID>:root", "arn:aws:iam::<계정ID>:saml-provider/<이름>"]
}}

resource "aws_iam_role" "{res}" {{
  name = "{iam_name(persona)}"

  # 비워두고 apply 하면 아무도 assume 할 수 없는 역할이 생깁니다(정책만 붙은 껍데기).
  assume_role_policy = jsonencode({{
    "Version" : "2012-10-17",
    "Statement" : [{{
      "Effect" : "Allow",
      "Principal" : {{ "AWS" : var.{res}_trusted_principals }},
      "Action" : "sts:AssumeRole"
    }}]
  }})
}}

resource "aws_iam_role_policy" "{res}" {{
  name   = "{iam_name(persona)}"
  role   = aws_iam_role.{res}.id
  policy = jsonencode({_canonical_json(doc)})
}}
"""
    return PolicyArtifact(
        persona=persona, target="iam_role_tf", label="IAM 역할 (.tf)",
        filename=f"{persona}.iam-role.tf", content=hcl, language="hcl",
        notes=[_ROLE_NOTE, *COMMON_NOTES],
    )


def permission_set_artifact(
    persona: str, description: str, policy_doc: dict, *, session_duration: str = "PT8H"
) -> PolicyArtifact:
    """IdC Permission Set 정의 + inline policy. account assignment 은 만들지 않는다(불변식 ①)."""
    doc = _statement_doc(policy_doc)
    res = tf_name(persona)
    header = _header(
        persona, description, doc,
        "IAM Identity Center(IdC)용 산출물. Permission Set 정의 + inline 정책만 만듭니다.\n"
        "# account assignment(어느 계정·그룹에 부여할지)은 의도적으로 생성하지 않습니다 — 사람이 수동으로.",
    )
    hcl = f"""{header}
resource "aws_ssoadmin_permission_set" "{res}" {{
  name             = "{iam_name(persona)}"
  description      = "LP2PS 최소권한 — {_hcl_safe(persona)}"
  instance_arn     = var.identity_center_instance_arn
  session_duration = "{session_duration}"
}}

resource "aws_ssoadmin_permission_set_inline_policy" "{res}" {{
  instance_arn       = var.identity_center_instance_arn
  permission_set_arn = aws_ssoadmin_permission_set.{res}.arn
  inline_policy      = jsonencode({_canonical_json(doc)})
}}

# account assignment 은 의도적으로 생성하지 않음 — 필요 시 사람이 수동으로 추가.
"""
    return PolicyArtifact(
        persona=persona, target="permission_set_tf", label="Permission Set (.tf)",
        filename=f"{persona}.permission-set.tf", content=hcl, language="hcl",
        notes=[_PS_NOTE, *COMMON_NOTES],
    )


def build_artifacts(
    persona: str,
    description: str,
    policy_doc: dict,
    *,
    uses_identity_center: bool = True,
    session_duration: str = "PT8H",
) -> list[PolicyArtifact]:
    """persona 정책 → 반영 산출물 목록(결정론 순서).

    `uses_identity_center=False` 면 Permission Set 산출물을 **넣지 않는다** — IdC 인스턴스가 없는
    고객에게 apply 불가한 `.tf` 를 주면 "이걸로 뭘 하라는 거냐"가 된다. 순서는 그 고객이 실제로
    쓸 것부터다(IAM 정책 → 정책 JSON → 역할 → PS).
    """
    artifacts = [
        iam_policy_artifact(persona, description, policy_doc),
        policy_json_artifact(persona, policy_doc),
        iam_role_artifact(persona, description, policy_doc),
    ]
    if uses_identity_center:
        artifacts.append(
            permission_set_artifact(persona, description, policy_doc, session_duration=session_duration)
        )
    return artifacts


def build_bulk_iam_policies(entries: list[tuple[str, dict]]) -> str:
    """persona 전체 → `iac/iam_policies.tf` 한 장(관리형 정책 N개).

    `entries` = [(persona, policy_doc)]. 호출자가 정렬해 넘긴다(결정론은 호출자 책임 — M7 은 이미
    persona 정렬을 한다). Statement 가 빈 persona 는 **건너뛴다** — 빈 정책은 apply 시 IAM 이 거부한다.

    역할(`iam_role_tf`)은 일괄로 내지 않는다: 신뢰정책이 persona 마다 달라 변수가 persona 수만큼
    필요해지고, 대부분의 non-IdC 고객은 이미 역할을 갖고 있어 **정책만 갈아끼우면 된다**.
    역할까지 필요한 persona 는 화면에서 개별로 내려받는다.
    """
    blocks: list[str] = []
    for persona, policy_doc in entries:
        doc = _statement_doc(policy_doc)
        if not doc.get("Statement"):
            continue
        blocks.append(_iam_policy_block(persona, doc))
    header = (
        "# 자동 생성 — LP2PS. 검토 후 apply 하세요.\n"
        "#\n"
        "# persona 별 최소권한을 **관리형 IAM 정책**으로 만듭니다(IdC 를 쓰지 않는 환경용).\n"
        "# 이 파일은 정책을 어디에도 attach 하지 않습니다 — 기존 역할·사용자에 사람이 붙이세요.\n"
        "#\n"
        "# 주의: Statement 의 Resource 는 \"*\" 입니다 — action 만 최소화했고 리소스 범위는\n"
        "#       좁히지 않았습니다. 각 정책은 그 persona 멤버 전원의 실사용 action 합집합입니다.\n"
        "# 여러 계정에 반영: 계정마다 apply 하세요(provider alias 또는 workspace).\n"
    )
    if not blocks:
        return header + "\n# 반영할 정책이 없습니다(모든 persona 의 Statement 가 비어 있음).\n"
    return header + "\n" + "\n".join(blocks)
