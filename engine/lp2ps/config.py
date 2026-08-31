"""고객 config 로더.

불변식 ④(고객 무관): 계정ID/ARN/persona명/임계치 등 고객별 리터럴은 오직
`config/<customer>.yaml` 에만 존재한다. 코드에는 어떤 고객 값도 하드코딩하지 않는다.
"""

from __future__ import annotations

import re
from pathlib import Path

from pydantic import BaseModel, Field, model_validator

# account/region 형식 허용목록. ARN 구성 전에 검증해 인젝션·오탈자 배포를 차단한다.
_ACCOUNT_RE = re.compile(r"^\d{12}$")
# AWS 표준 리전 패턴(예: us-west-2, ap-northeast-2, us-gov-east-1). 형식만 강제(존재 검증은 배포 시).
_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d$")


class EngineConfig(BaseModel):
    # 엔진 Lambda 런타임(zip 소스 패키징). 상승경로는 규칙 기반이라 대형 계정도 Lambda 로 충분.
    runtime: str = "lambda"


class ScheduleConfig(BaseModel):
    cron: str | None = None


class AiConfig(BaseModel):
    # false 면 도구는 결정론 전용으로 완전 동작 (하네스 단락).
    enabled: bool = False
    # Bedrock 추론 프로파일 ID(온디맨드 미지원 모델은 us. 프리픽스 필요). 고객 무관 config.
    model: str = "us.anthropic.claude-haiku-4-5-20251001-v1:0"


class ProvisioningConfig(BaseModel):
    # PS '정의' 생성 게이트는 config 가 아니라 런타임(approved persona + UI 2차·최종 확인).
    # IdC 인스턴스 ARN 은 런타임 자동 조회. account assignment 는 안 함(불변식①).
    # IdC 는 계정당 한 리전에만 활성화되며 config.region 과 다를 수 있다(예: IdC=us-east-1,
    # 분석=us-west-2). IdC 조회·PS 생성에 쓸 리전. 비우면 config.region 사용.
    idc_region: str = ""


class RiskRules(BaseModel):
    """M4 위험 점수 규칙 — 임계치 + 가중치(0-100 스케일로 합산 후 클램프).

    불변식 ②(결정론): 점수는 이 가중치의 합이며 wall-clock/random 없음. 근거는 risk_audit.jsonl 에
    rule→weight→contribution 으로 남긴다. 모든 리터럴은 config 에만(불변식 ④).
    """

    # 임계치
    long_lived_key_days: int = 90
    unused_action_days: int = 90
    # 위험 가중치(각 규칙이 hit 하면 더해지는 점수)
    weight_long_lived_key: int = 20
    weight_no_mfa: int = 15
    weight_unused_permission: int = 1  # 미사용 action 1건당(상한 있음)
    weight_unused_permission_cap: int = 25  # 미사용 누적 가중 상한
    weight_escalation_path: int = 30  # 상승경로 1건당
    weight_escalation_cap: int = 40
    weight_wildcard_action: int = 20  # granted 에 '*' 와일드카드 존재
    weight_admin_like: int = 25  # AdministratorAccess 급 광범위 권한
    # risk_level 경계(점수 이상이면 해당 레벨)
    level_critical: int = 75
    level_high: int = 50
    level_medium: int = 25


class CatalogConfig(BaseModel):
    """M5 persona 군집 파라미터."""

    # fingerprint = 사용 action 의 서비스 접두 집합. 이 최소 인원 미만 군집은 개별(기타)로.
    min_members_for_persona: int = 2
    # 신뢰정책이 AWS 서비스인 역할(Lambda/EC2/SSM 실행 역할 등)을 persona 군집에서 제외한다.
    # persona 는 **사람** 접근의 표준화 단위이고, 서비스 역할은 사람이 로그인할 수 없어 Permission Set
    # 대상이 아니다. 섞이면 (a) 서비스 전용 action 이 사람용 정책에 합성되고, (b) 서비스 역할 수가
    # min_members_for_persona 를 채워 실재하지 않는 persona 가 생긴다.
    # false 로 되돌리면 종전(서비스 역할 포함) 동작 — persona 수·멤버 수가 크게 늘어난다.
    exclude_service_roles: bool = True
    # IaC 도구가 만든 **배포 전용 역할**을 persona 군집에서 이름 패턴으로 제외한다(fnmatch, 대소문자 구분).
    #
    # 왜 필요한가: CDK bootstrap 의 deploy/file-publishing/lookup 역할은 신뢰정책이 `Principal.AWS`
    # (배포 계정 root)뿐이라 `principal_kind`=unknown 으로 남아 위 서비스 역할 제외를 통과한다. 그리고
    # 리전마다 3개씩 생기므로 스스로 `min_members_for_persona` 를 채워 **실재하지 않는 persona** 를
    # 만든다(실측: InfraReadOnlyPersona 3/3, InfraWritePersona 4/4 가 전부 배포 역할이었다).
    #
    # 왜 이름 패턴인가: CFN 스택 역추적(`cloudformation:ListStacks`/`ListStackResources`)은 멤버 role
    # 정책 확장 → **고객 재배포**를 요구하는데, 그래도 Terraform 이 만든 역할은 못 잡는다. 패턴은
    # config 만으로 되고 어느 IaC 든 명명 규약만 알면 잡힌다.
    #
    # 기본값은 **AWS 도구의 공개 명명 규약**만 담는다(특정 고객 값이 아니다 — 불변식 ④). 고객 사내
    # 배포 역할 규약은 yaml 에서 덧붙인다.
    # 매칭 대상 = 이름(ARN 마지막 세그먼트)과 전체 ARN 둘 다. persona 에서 빠져도 조치 필요 항목
    # (미사용 역할·장기 키·MFA)에는 그대로 남는다 — 제외는 "사람 표준화 대상 아님"이지 "무해"가 아니다.
    exclude_principal_patterns: list[str] = Field(
        default_factory=lambda: [
            "cdk-*-deploy-role-*",
            "cdk-*-file-publishing-role-*",
            "cdk-*-image-publishing-role-*",
            "cdk-*-lookup-role-*",
        ]
    )
    # persona 신뢰도: CloudTrail(고신뢰) 기반이면 높게, fallback 이면 낮게.
    confidence_access_analyzer: float = 0.9
    confidence_fallback: float = 0.5


class PermissionSetConfig(BaseModel):
    """M7 IaC — persona → Identity Center Permission Set 매핑 기본값."""

    session_duration: str = "PT8H"  # ISO8601 duration
    # persona 별 세션 시간 오버라이드(persona 명 → duration). 없으면 위 기본값.
    session_duration_overrides: dict[str, str] = Field(default_factory=dict)


class Config(BaseModel):
    customer: str
    region: str = "us-west-2"

    # cross_account 는 대상 계정 자격증명 획득 방식만 결정한다(분석 로직·산출물은 동일).
    #  - false(기본): ambient 자격증명(현재 실행 계정 자신을 assume 없이 분석). accounts=["self"].
    #  - true: config.accounts 의 각 계정에 readonly_role_name 을 sts:AssumeRole 해 수집(멀티계정).
    cross_account: bool = False
    accounts: list[str] = Field(default_factory=lambda: ["self"])

    readonly_role_name: str | None = None
    # cross-account assume 시 confused-deputy 방어용 ExternalId(옵션). 멤버 계정 role
    # trust policy 의 sts:ExternalId 조건과 일치해야 assume 성공. 설정 시 assume_role 에 전달.
    external_id: str | None = None

    engine: EngineConfig = Field(default_factory=EngineConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    provisioning: ProvisioningConfig = Field(default_factory=ProvisioningConfig)
    risk_rules: RiskRules = Field(default_factory=RiskRules)
    catalog: CatalogConfig = Field(default_factory=CatalogConfig)
    permission_sets: PermissionSetConfig = Field(default_factory=PermissionSetConfig)

    @model_validator(mode="after")
    def _check_accounts(self) -> "Config":
        if not self.accounts:
            raise ValueError("config.accounts 가 비어 있습니다.")
        # region 형식 검증(ARN·엔드포인트 구성 전).
        if not _REGION_RE.match(self.region):
            raise ValueError(f"region 형식이 올바르지 않습니다: {self.region!r}")
        if not self.cross_account and self.accounts != ["self"]:
            raise ValueError('cross_account=false 이면 accounts 는 ["self"] 여야 합니다.')
        if self.cross_account:
            if "self" in self.accounts:
                raise ValueError('cross_account=true 이면 accounts 에 실제 계정 ID 를 넣어야 합니다("self" 불가).')
            if not self.readonly_role_name:
                raise ValueError("cross_account=true 이면 readonly_role_name 이 필요합니다.")
            # 각 account 는 정확히 12자리 숫자여야 함("self" 는 cross_account=false 경로 전용).
            for acct in self.accounts:
                if not _ACCOUNT_RE.match(acct):
                    raise ValueError(f"account 형식이 올바르지 않습니다(12자리 숫자 필요): {acct!r}")
        return self


def load_config(path: str | Path) -> Config:
    """YAML 파일을 읽어 검증된 Config 를 반환.

    yaml import 는 여기서 지연 로드한다 — API Lambda 는 config 파일을 읽지 않고 env inline JSON 만
    쓰므로(RiskRules/ProvisioningConfig 모델만 사용), API 레이어에 pyyaml 이 없어도 동작해야 한다.
    """
    import yaml

    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"config 파일이 없습니다: {p}")
    data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
    return Config.model_validate(data)
