/**
 * config-loader passthrough assertions (run with ts-node via `npm test`, no jest).
 *
 * 엔진 전용 튜너블(risk_rules/catalog/permission_sets/collection)은 CDK 가 스키마를 소유하지 않고
 * yaml 을 그대로 `LP2PS_CONFIG_INLINE` 로 흘려보낸다. 여기서 한 키를 빠뜨리면 **아무 것도 실패하지
 * 않는다** — 엔진 pydantic 이 기본값을 채우고, 수집은 성공하며, 소스 상태도 ok 다. 실제로 그렇게
 * 새어나갔다: `collection.cloudtrail_max_pages: 400` 으로 배포했는데 라이브 실행의 소스 상태에는
 * "페이지 상한(200) 도달"(코드 기본값)이 찍혔다. 엔진 쪽 배선 테스트(test_selfmode)는 CDK 를 거치지
 * 않으므로 이 구간을 볼 수 없다.
 *
 * 그래서 이 테스트는 두 방향을 함께 잠근다:
 *   - yaml 에 있는 튜너블은 전부 로더를 통과해야 한다(누락 = 조용한 기본값 폴백)
 *   - yaml 에 없는 튜너블은 키 자체가 없어야 한다(빈 객체를 실으면 엔진 기본값을 덮어쓴다)
 */
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import { loadConfig } from "../lib/config-loader";

function assert(cond: boolean, msg: string): void {
  if (!cond) {
    console.error(`✗ FAIL: ${msg}`);
    process.exitCode = 1;
  } else {
    console.log(`✓ ${msg}`);
  }
}

function writeConfig(body: string): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "lp2ps-cfg-"));
  const p = path.join(dir, "c.yaml");
  fs.writeFileSync(p, body);
  return p;
}

const BASE = `customer: t
region: us-east-1
cross_account: false
accounts:
  - self
`;

// --- 모든 엔진 튜너블이 통과한다 ---
const full = loadConfig(
  writeConfig(
    BASE +
      `collection:
  cloudtrail_max_pages: 400
risk_rules:
  unused_action_days: 45
catalog:
  min_members_for_persona: 3
permission_sets:
  session_duration: PT4H
`,
  ),
);
assert(full.collection?.cloudtrail_max_pages === 400, "collection.cloudtrail_max_pages 가 로더를 통과한다");
assert(full.risk_rules?.unused_action_days === 45, "risk_rules 가 로더를 통과한다");
assert(full.catalog?.min_members_for_persona === 3, "catalog 가 로더를 통과한다");
assert(full.permission_sets?.session_duration === "PT4H", "permission_sets 가 로더를 통과한다");

// Lambda 로 실제 전달되는 형태(JSON) 에도 남아 있어야 한다 — 엔진은 이 문자열만 본다.
const inline = JSON.parse(JSON.stringify(full));
assert(inline.collection?.cloudtrail_max_pages === 400, "직렬화된 LP2PS_CONFIG_INLINE 에 collection 이 남는다");

// --- 대조군: yaml 에 없으면 키를 만들지 않는다 ---
const bare = loadConfig(writeConfig(BASE));
assert(!("collection" in bare), "yaml 에 collection 이 없으면 키를 싣지 않는다(엔진 기본값 보존)");
assert(!("risk_rules" in bare), "yaml 에 risk_rules 가 없으면 키를 싣지 않는다");
