/**
 * config/<customer>.yaml 로더 (엔진 Python config 와 형태 일치).
 *
 * 불변식 ④(고객 무관): 계정ID·ARN·persona명·임계치는 오직 config yaml 에만. CDK 코드에 고객 값
 * 하드코딩 금지. bin/lp2ps.ts 가 `-c config=...` 컨텍스트로 경로를 받아 이 로더로 타입화한다.
 */
import * as fs from "fs";
import * as path from "path";
import * as yaml from "js-yaml";

export interface EngineConfig {
  runtime: string; // "lambda" (fargate 는 제거됨 — 상승경로 규칙 기반이라 Lambda 로 충분)
}

export interface ScheduleConfig {
  cron: string | null;
}

export interface AiConfig {
  enabled: boolean;
  model: string;
}

export interface ProvisioningConfig {
  // PS 정의 생성 게이트는 런타임(approved + UI 확인). config 는 IdC 리전만(선택).
  idc_region?: string;
  // IdC(Identity Center) 사용 여부. false 면 Permission Set 산출물을 만들지 않고 관리형 IAM
  // 정책/역할 Terraform 만 낸다(IdC 인스턴스가 없으면 PS .tf 는 apply 자체가 불가능하다).
  // 생략 시 엔진 기본값 true — 기존 배포의 동작이 바뀌지 않는다.
  uses_identity_center?: boolean;
}

// 아래 3개(risk_rules/catalog/permission_sets)는 **엔진 전용 튜너블**이다. 스키마·기본값의 단일
// 소스는 engine/lp2ps/config.py 이며, CDK 는 값을 정의·검증하지 않고 yaml 을 그대로 통과시켜
// LP2PS_CONFIG_INLINE 으로 엔진에 전달만 한다(엔진 pydantic 이 누락 필드에 기본값을 채운다).
// 따라서 여기선 전부 optional 이고, yaml 에 없으면 JSON.stringify 에서 생략된다(드리프트 방지).
export interface RiskRulesConfig {
  long_lived_key_days?: number;
  unused_action_days?: number;
  weight_long_lived_key?: number;
  weight_no_mfa?: number;
  weight_unused_permission?: number;
  weight_unused_permission_cap?: number;
  weight_escalation_path?: number;
  weight_escalation_cap?: number;
  weight_wildcard_action?: number;
  weight_admin_like?: number;
  level_critical?: number;
  level_high?: number;
  level_medium?: number;
}

export interface CatalogClusterConfig {
  min_members_for_persona?: number;
  confidence_access_analyzer?: number;
  confidence_fallback?: number;
}

export interface PermissionSetConfig {
  session_duration?: string;
  session_duration_overrides?: Record<string, string>;
}

export interface Lp2psConfig {
  customer: string;
  region: string;
  cross_account: boolean;
  accounts: string[];
  readonly_role_name: string | null;
  // cross-account assume 시 confused-deputy 방어용 ExternalId(옵션). 멤버 계정 role trust policy 의
  // sts:ExternalId 조건과 일치해야 assume 성공. 엔진 전용 — 배포 엔진에 반드시 전달돼야 방어가 실동작.
  external_id?: string | null;
  engine: EngineConfig;
  schedule: ScheduleConfig;
  ai: AiConfig;
  provisioning: ProvisioningConfig;
  // 엔진 전용 튜너블(passthrough — 위 인터페이스 주석 참고).
  risk_rules?: RiskRulesConfig;
  catalog?: CatalogClusterConfig;
  permission_sets?: PermissionSetConfig;
}

const DEFAULTS = {
  region: "us-west-2",
  cross_account: false,
  readonly_role_name: null,
  engine: { runtime: "lambda" },
  schedule: { cron: null },
  ai: { enabled: false, model: "us.anthropic.claude-haiku-4-5-20251001-v1:0" },
  provisioning: {},
};

export function loadConfig(configPath: string): Lp2psConfig {
  const resolved = path.resolve(configPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`config 파일이 없습니다: ${resolved}`);
  }
  const raw = (yaml.load(fs.readFileSync(resolved, "utf-8")) ?? {}) as Record<string, unknown>;

  const cfg: Lp2psConfig = {
    customer: requireString(raw, "customer"),
    region: (raw.region as string) ?? DEFAULTS.region,
    cross_account: (raw.cross_account as boolean) ?? DEFAULTS.cross_account,
    accounts: (raw.accounts as string[]) ?? ["self"],
    readonly_role_name: (raw.readonly_role_name as string | null) ?? DEFAULTS.readonly_role_name,
    engine: { ...DEFAULTS.engine, ...(raw.engine as object) },
    schedule: { ...DEFAULTS.schedule, ...(raw.schedule as object) },
    ai: { ...DEFAULTS.ai, ...(raw.ai as object) },
    provisioning: { ...DEFAULTS.provisioning, ...(raw.provisioning as object) },
  };

  // 엔진 전용 튜너블(external_id/risk_rules/catalog/permission_sets)은 CDK 가 스키마를 정의하지
  // 않고, yaml 에 **존재할 때만** 그대로 통과시킨다(엔진 config.py 가 SSOT·기본값 소유). 없는 키를
  // 넣으면 JSON.stringify 후 엔진 pydantic 의 기본값을 빈 값으로 덮어써 버리므로 조건부로만 싣는다.
  if (raw.external_id != null) cfg.external_id = raw.external_id as string;
  if (raw.risk_rules != null) cfg.risk_rules = raw.risk_rules as RiskRulesConfig;
  if (raw.catalog != null) cfg.catalog = raw.catalog as CatalogClusterConfig;
  if (raw.permission_sets != null) cfg.permission_sets = raw.permission_sets as PermissionSetConfig;

  validate(cfg);
  return cfg;
}

function requireString(obj: Record<string, unknown>, key: string): string {
  const v = obj[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`config.${key} 는 필수 문자열입니다.`);
  }
  return v;
}

// account/region 형식 허용목록(ARN 구성·배포 전 검증). 엔진 config.py 와 동일 규칙.
const ACCOUNT_RE = /^\d{12}$/;
const REGION_RE = /^[a-z]{2}(-[a-z]+)+-\d$/;

function validate(cfg: Lp2psConfig): void {
  if (cfg.accounts.length === 0) {
    throw new Error("config.accounts 가 비어 있습니다.");
  }
  if (!REGION_RE.test(cfg.region)) {
    throw new Error(`config.region 형식이 올바르지 않습니다: ${cfg.region}`);
  }
  if (!cfg.cross_account && !(cfg.accounts.length === 1 && cfg.accounts[0] === "self")) {
    throw new Error('cross_account=false 이면 accounts 는 ["self"] 여야 합니다.');
  }
  if (cfg.cross_account) {
    if (!cfg.readonly_role_name) {
      throw new Error("cross_account=true 이면 readonly_role_name 이 필요합니다.");
    }
    // "self" 는 cross_account=false 전용. cross_account=true 면 각 account 는 12자리 숫자.
    for (const acct of cfg.accounts) {
      if (!ACCOUNT_RE.test(acct)) {
        throw new Error(`config.accounts 형식이 올바르지 않습니다(12자리 숫자 필요): ${acct}`);
      }
    }
  }
}

/** customer 를 CloudFormation 스택명 prefix 로 안전하게 정제(다중 배포 충돌 방지). */
export function stackPrefix(customer: string): string {
  const cleaned = customer.replace(/[^a-zA-Z0-9]/g, "-").replace(/^-+|-+$/g, "");
  return cleaned.length > 0 ? `Lp2ps-${cleaned}` : "Lp2ps";
}
