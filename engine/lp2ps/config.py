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

# 테넌트 그룹(R5) 을 선언하지 않은 config 의 기본 그룹. 단일 고객 배포는 전 계정이 이 그룹이 되고,
# 그러면 `internal`/`cross_tenant` 판정이 종전 동작("config 에 있으면 우리 계정")과 같아진다.
DEFAULT_TENANT_GROUP = "default"
# 그룹 이름은 산출물 파일명·경로·화면 라벨에 그대로 쓰인다 → 경로 조작·구분자 충돌을 막기 위해
# 문자 집합을 제한한다(고객 식별 문자열이 경로가 되는 자리다).
_GROUP_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


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

    # 이 고객이 IAM Identity Center 를 쓰는가. **산출물의 종류를 가른다** — false 면 Permission Set
    # 은 만들 수 없으므로(IdC 인스턴스가 없다) 관리형 IAM 정책/역할 Terraform 만 낸다. true(기본)면
    # 기존 동작 그대로 PS 산출물을 함께 낸다.
    #
    # 왜 config 인가: 데이터로 추론하면(예: sso_ps principal 이 하나도 없으면 IdC 미사용) IdC 를 막
    # 도입해 아직 할당이 없는 고객을 미사용으로 오판한다. 고객이 선언하는 값이다(불변식 ④).
    # 이 값은 PS 마이그레이션 KPI 표시 여부에도 쓴다.
    uses_identity_center: bool = True


class CollectionConfig(BaseModel):
    """M1 수집 예산 — 고객 환경(계정 수·API 활동량)에 따라 조정해야 하는 값들.

    왜 config 인가: 이 상한은 고객의 계정 수와 활동량에 달렸고, 코드에 박으면 계정이 3개인
    고객과 200개인 고객이 같은 예산을 쓴다(불변식 ④ — 임계치는 config 에만).

    **왜 상한이 아예 필요한가:** LookupEvents 는 페이지당 최대 50건인데 초당 ≈2회로 제한돼
    페이지당 약 0.5초가 든다. 활동이 많은 계정의 90일 관리 이벤트를 끝까지 훑으려면 수만
    페이지(수 시간)가 필요해 어떤 상한을 골라도 90일 완주는 불가능하다 — 상한은 "얼마나
    받아낼 것인가"가 아니라 "정해진 시간 안에 끝낼 것인가"의 문제다. collect 단계는 전 계정을
    한 Lambda 에서 순차 처리하며 타임아웃이 15분이므로(`infra/lib/engine-stack.ts`), 안전한
    예산은 대략 `900초 / (0.5초 × 계정수)` 페이지다.

    LookupEvents 는 **최신순**이라 상한에 걸려 버려지는 것은 가장 오래된 이벤트다. 따라서
    상한을 낮게 두면 산출물의 CloudTrail 근거가 최근 며칠로 좁아지는 것이지, 무작위로
    누락되는 것이 아니다. 실제로 덮은 기간은 raw 의 `coverage_start` 로 기록된다.
    """

    # 계정·리전당 LookupEvents 페이지 상한. 페이지 **수**여야 한다(초 단위 예산으로 바꾸면
    # 실행 속도에 따라 절단 지점이 달라져 불변식 ②(결정론)가 깨진다).
    cloudtrail_max_pages: int = 200
    # LookupEvents 에 **요청하는** 소급 기간(일). 상한(`cloudtrail_max_pages`)에 걸리면 실제로
    # 덮는 구간은 이보다 훨씬 짧아진다 — 그 실측값이 raw 의 `coverage_start` 이고, 산출물은
    # 요청값이 아니라 실측 구간을 표시한다(`PrincipalRecord.observed_days`).
    cloudtrail_window_days: int = 90

    @model_validator(mode="after")
    def _check_budget(self) -> "CollectionConfig":
        if self.cloudtrail_max_pages < 1:
            raise ValueError("collection.cloudtrail_max_pages 는 1 이상이어야 합니다.")
        if self.cloudtrail_window_days < 1:
            raise ValueError("collection.cloudtrail_window_days 는 1 이상이어야 합니다.")
        return self


class RiskRules(BaseModel):
    """M4 위험 점수 규칙 — 임계치 + 가중치(0-100 스케일로 합산 후 클램프).

    불변식 ②(결정론): 점수는 이 가중치의 합이며 wall-clock/random 없음. 근거는 risk_audit.jsonl 에
    rule→weight→contribution 으로 남긴다. 모든 리터럴은 config 에만(불변식 ④).
    """

    # 임계치
    long_lived_key_days: int = 90
    # ---- 미사용 등급(R2) ----
    # 등급 경계(일). [watch 시작, review 시작, cleanup 시작] — 오름차순·양수 강제.
    # 코드에 박으면 안 된다: "90일 미사용" 의 적정값은 고객 운영 주기에 달렸다(불변식 ④).
    unused_tier_days: list[int] = Field(default_factory=lambda: [30, 60, 90])
    # `unused_role` finding 의 경계. 기본은 cleanup 등급 시작값과 같다 — 다르게 두면 화면의
    # "정리 권고" 등급과 백로그 항목 수가 어긋나 같은 계정을 놓고 두 숫자가 싸운다.
    unused_role_days: int = 90
    # 생성 후 이 일수 미만이면 등급을 유보한다(`new`). 어제 만든 역할에 사용 기록이 없는 것은
    # 당연하고, 그것을 "미사용 역할이니 삭제" 로 권고하면 배포 중인 것을 지우게 한다.
    new_principal_days: int = 30
    # ⚠️ 아래 `unused_action_days` 는 종전에 unused_role / new_role_unused 를 가르는 값이었다.
    # 신 설계에서는 그 역할이 `new_principal_days`(신규 유보)와 `unused_role_days`(정리 경계)로
    # 갈라진다. P2 에서 배선을 옮길 때까지 남겨 둔다(기존 run 재현성).
    # "미사용이니 삭제하라"고 말하기 위해 필요한 **최소 관측 가능 기간**(일 = principal 생성 후 경과일).
    # 이보다 어린 principal 은 사용 기록이 없는 게 당연하다 — 생성 3일 된 역할을 "미사용 역할, 삭제
    # 후보" 로 내면 배포 중인 것을 지우라고 권하는 셈이다. M6 이 unused_role / new_role_unused 를
    # 이 값으로 가른다. (오래 dead 키였다 — 값은 있는데 읽는 코드가 없었고, 그동안 화면의 "90일"은
    # 어디서도 측정되지 않은 숫자였다.)
    unused_action_days: int = 90
    # 위험 가중치(각 규칙이 hit 하면 더해지는 점수)
    weight_long_lived_key: int = 20
    weight_no_mfa: int = 15
    weight_unused_permission: int = 1  # 미사용 action 1건당(상한 있음)
    weight_unused_permission_cap: int = 25  # 미사용 누적 가중 상한
    weight_escalation_path: int = 30  # 상승경로 1건당
    weight_escalation_cap: int = 40
    weight_wildcard_action: int = 20  # granted 에 '*' 와일드카드 존재
    # 신뢰정책이 `Principal:"*"` 등 광범위(R4). granted 와일드카드와 **다른 결함**이라 별 가중치다 —
    # 전자는 "이 역할이 무엇을 할 수 있나", 후자는 "누가 이 역할을 집을 수 있나" 다.
    weight_trust_policy_wildcard: int = 30
    weight_admin_like: int = 25  # AdministratorAccess 급 광범위 권한
    # risk_level 경계(점수 이상이면 해당 레벨)
    level_critical: int = 75
    level_high: int = 50
    level_medium: int = 25

    @model_validator(mode="after")
    def _check_unused_tiers(self) -> "RiskRules":
        if len(self.unused_tier_days) != 3:
            raise ValueError(
                "risk_rules.unused_tier_days 는 [watch, review, cleanup] 3개 값이어야 합니다."
            )
        if self.unused_tier_days[0] < 1:
            raise ValueError("risk_rules.unused_tier_days 값은 1 이상이어야 합니다.")
        # 오름차순이 아니면 등급 판정이 특정 등급을 도달 불가로 만든다(예: [60,30,90] → watch 가 없다).
        if sorted(self.unused_tier_days) != self.unused_tier_days or len(
            set(self.unused_tier_days)
        ) != 3:
            raise ValueError("risk_rules.unused_tier_days 는 서로 다른 값의 오름차순이어야 합니다.")
        if self.new_principal_days < 1:
            raise ValueError("risk_rules.new_principal_days 는 1 이상이어야 합니다.")
        if self.unused_role_days < 1:
            raise ValueError("risk_rules.unused_role_days 는 1 이상이어야 합니다.")
        return self


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
    # 매칭 대상 = 이름(ARN 마지막 세그먼트)과 전체 ARN 둘 다.
    #
    # 🔴 이 패턴은 persona 군집뿐 아니라 **조치 필요 항목에서도** 대상을 뺀다
    # (`m6_reporter.cleanup_group_of` 의 R6 게이트 — `excluded_reason == "iac_bootstrap_role"` 은
    # 그룹 없음). 부트스트랩 역할에 "삭제"·"와일드카드 재작성" 을 권하면 고객의 배포가 깨진다.
    # 빠진 사실은 '제외 내역'(`summarize_exclusions`)에 건수와 사유로 남는다 — 조용히 사라지지 않는다.
    exclude_principal_patterns: list[str] = Field(
        default_factory=lambda: [
            "cdk-*-deploy-role-*",
            "cdk-*-file-publishing-role-*",
            "cdk-*-image-publishing-role-*",
            "cdk-*-lookup-role-*",
            # 🔴 `cdk bootstrap` 이 만드는 다섯 번째 역할. 빠져 있어서 라이브에서 **삭제 권고까지
            #    올라왔다**(미사용 96일 · critical, 리전별로 하나씩): 지우면 그 리전으로의 CFN 배포가
            #    전부 실패한다. 나머지 넷과 달리 신뢰 대상이 `cloudformation.amazonaws.com` 이라
            #    "서비스 역할" 로 보이지만, 서비스 역할 제외는 트랙 배정에만 쓰이고 미사용 판정을
            #    막지 않는다 — 그래서 이름 패턴에 있어야 한다.
            "cdk-*-cfn-exec-role-*",
        ]
    )
    # 접근 성격(축2) 판정 임계치. 코드 리터럴이 아니라 config 여야 한다(불변식 ④) — 고객 환경마다
    # "광범위"의 기준이 다르다(서비스 20종이 관리자인 계정도, 50종이 평범한 계정도 있다).
    admin_min_services_with_identity: int = 20  # IAM/SSO/Organizations 쓰기 + 서비스 N종 이상 → Admin
    admin_min_services: int = 50  # identity 쓰기 없어도 서비스 N종 이상 광범위 → Admin
    write_ratio_threshold: float = 0.15  # 변경 동사 비중 ≥ 이 값이면 Write, 미만이면 ReadOnly
    # 관측 구간이 이 일수 미만이면 화면이 **호출 횟수를 표기하지 않는다**(사용자 결정 2026-09-11:
    # *"관측 기간이 몇 시간이면 표기를 안 해주는 게 맞다. 오히려 고객의 신뢰를 무너뜨린다."*).
    # CloudTrail LookupEvents 는 페이지 상한이 있어 이벤트가 많은 계정에서는 구간이 몇 시간뿐이다
    # (실측 4.4시간 → `observed_window_days = 0`). 그런 창의 "3회" 는 총 사용 횟수가 아니다.
    # 횟수를 감춘 자리의 정본은 `last_used`(Access Advisor 는 최대 400일, 잘리지 않는다).
    # 🔴 `count_observed` 자체는 산출물에 그대로 남는다 — 화면 표기만 조건부다.
    count_min_observed_days: int = 7

    @model_validator(mode="after")
    def _check_profile_thresholds(self) -> "CatalogConfig":
        if self.admin_min_services_with_identity < 1 or self.admin_min_services < 1:
            raise ValueError("catalog.admin_min_services* 는 1 이상이어야 합니다.")
        if not 0.0 <= self.write_ratio_threshold <= 1.0:
            raise ValueError("catalog.write_ratio_threshold 는 0.0~1.0 범위여야 합니다.")
        if self.count_min_observed_days < 0:
            raise ValueError("catalog.count_min_observed_days 는 0 이상이어야 합니다.")
        return self


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
    # 🔴 두 형태를 받는다(R5). 로더는 항상 **계정 ID 문자열 목록**으로 정규화하므로 이 값을 순회하는
    # 하위 코드(수집 루프 등)는 변경이 필요 없다. 그룹은 `account_groups` 로 따로 나온다.
    #   accounts: ["1111…", "2222…"]                        → 전부 DEFAULT_TENANT_GROUP
    #   accounts: [{id: "1111…", group: "customerA"}, …]     → 선언한 그룹
    # 혼합도 허용한다(그룹 없는 항목은 기본 그룹).
    accounts: list[str] = Field(default_factory=lambda: ["self"])
    # 계정 ID → 테넌트 그룹. **파생값이다** — yaml 에 직접 쓰지 말고 `accounts[].group` 으로 선언한다
    # (직접 쓰면 아래 정규화가 덮어쓴다). 목록에 없는 계정은 `tenant_group_of` 가 빈 문자열을 준다:
    # "모른다" 와 "기본 그룹" 을 같은 값으로 만들면 수집 범위 밖 계정을 신뢰해도 internal 로 보인다.
    account_groups: dict[str, str] = Field(default_factory=dict)

    readonly_role_name: str | None = None
    # cross-account assume 시 confused-deputy 방어용 ExternalId(옵션). 멤버 계정 role
    # trust policy 의 sts:ExternalId 조건과 일치해야 assume 성공. 설정 시 assume_role 에 전달.
    external_id: str | None = None

    engine: EngineConfig = Field(default_factory=EngineConfig)
    schedule: ScheduleConfig = Field(default_factory=ScheduleConfig)
    ai: AiConfig = Field(default_factory=AiConfig)
    provisioning: ProvisioningConfig = Field(default_factory=ProvisioningConfig)
    collection: CollectionConfig = Field(default_factory=CollectionConfig)
    risk_rules: RiskRules = Field(default_factory=RiskRules)
    catalog: CatalogConfig = Field(default_factory=CatalogConfig)
    permission_sets: PermissionSetConfig = Field(default_factory=PermissionSetConfig)

    @model_validator(mode="before")
    @classmethod
    def _normalize_accounts(cls, data: object) -> object:
        """`accounts` 의 dict 형태(`{id, group}`)를 ID 목록 + `account_groups` 로 분해한다.

        하위호환: 문자열 목록은 그대로 통과하고 전 항목이 `DEFAULT_TENANT_GROUP` 이 된다 →
        기존 고객 config 는 한 글자도 고치지 않아도 종전과 동일하게 동작한다.
        """
        if not isinstance(data, dict):
            return data
        raw = data.get("accounts")
        if not isinstance(raw, list):
            return data  # 타입 오류는 아래 필드 검증이 보고한다.
        ids: list[str] = []
        groups: dict[str, str] = {}
        for item in raw:
            if isinstance(item, str):
                acct, group = item, DEFAULT_TENANT_GROUP
            elif isinstance(item, dict):
                acct = item.get("id")
                group = item.get("group") or DEFAULT_TENANT_GROUP
                if not isinstance(acct, str) or not acct:
                    raise ValueError("config.accounts 항목에 id 가 없습니다.")
                if not isinstance(group, str) or not _GROUP_RE.match(group):
                    raise ValueError(
                        f"accounts[].group 형식이 올바르지 않습니다(영숫자·.-_ 1~64자): {group!r}"
                    )
                unknown = set(item) - {"id", "group"}
                if unknown:
                    # 오탈자를 조용히 무시하면 그룹 선언이 누락된 채 전 계정이 기본 그룹으로 합쳐진다.
                    raise ValueError(f"accounts[] 항목에 알 수 없는 키: {sorted(unknown)}")
            else:
                raise ValueError(f"config.accounts 항목 형식이 올바르지 않습니다: {item!r}")
            if acct in groups and groups[acct] != group:
                raise ValueError(f"같은 계정에 서로 다른 그룹이 선언되었습니다: {acct!r}")
            if acct not in groups:
                ids.append(acct)
            groups[acct] = group
        data["accounts"] = ids
        data["account_groups"] = groups  # 파생값 — yaml 에 직접 쓴 값이 있어도 덮어쓴다.
        return data

    def tenant_group_of(self, account_id: str) -> str:
        """계정 ID → 테넌트 그룹. 수집 범위 밖 계정은 **빈 문자열**(= 모른다).

        ⚠️ `cross_account=false` 모드에서는 `accounts=["self"]` 라 실제 계정 ID 를 config 가 모른다
        (런타임 STS 로 알아낸다) → 이 조회는 "" 를 준다. 호출자가 자기 계정을
        `DEFAULT_TENANT_GROUP` 으로 취급한다. 여기서 임의로 기본 그룹을 반환하면 **어떤 계정 ID 든**
        내부로 판정돼(신뢰정책이 가리키는 남의 계정까지) R5 의 fail-safe 가 뒤집힌다.
        """
        return self.account_groups.get(account_id, "")

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
