# LP2PS 빠른 배포 가이드 (원클릭 스크립트)

이 문서는 **`deploy-all.sh` 스크립트로 LP2PS를 한 번에 배포하는 방법**을 설명합니다.
단계별로 나눠 배포하면서 각 과정을 이해하고 싶다면 상세 가이드 **`docs/deployment-guide.md`** 를 보세요.
이 문서는 "빨리 띄우기"에 집중합니다.

> 스크립트는 순수 bash입니다. **Claude Code나 다른 도구는 필요 없습니다** — 터미널만 있으면 됩니다.

---

## 0. 사전 준비 (한 번만)

### 0-1. 로컬 도구 설치
`aws-cli(v2), node(18+), python(3.11+), git` 이 필요합니다. 확인:
```bash
aws --version && node --version && python3 --version && git --version
```
없으면 설치하세요(OS별 상세는 `docs/deployment-guide.md` 1단계 참고):
- **macOS**: `brew install awscli node python@3.12 git`
- **Windows**: awscli.amazonaws.com / nodejs.org(LTS) / python.org(설치 시 "Add to PATH" 체크) / git-scm.com
- **Linux(Ubuntu)**: `sudo apt install -y python3 python3-pip git` + AWS CLI v2 및 Node 20 설치

### 0-2. AWS 로그인 (도구 계정, 관리자 권한)
```bash
aws configure sso          # SSO 방식(권장). start URL과 리전은 조직 관리자에게 문의하세요.
# 또는  aws configure       # IAM 액세스 키 방식
aws sts get-caller-identity # 대상 계정 ID가 맞는지 확인
```
SSO를 사용했다면 프로필을 활성화하세요: `export AWS_PROFILE=<프로필명>`
(세션이 만료되면 `aws sso login --profile <프로필명>` 으로 재인증)

### 0-3. 소스 + 의존성 (한 번만)
```bash
git clone <리포 URL> lp2ps && cd lp2ps
cd infra && npm install && cd ..
cd frontend && npm install && cd ..
python3 -m venv engine/.venv && engine/.venv/bin/pip install -e 'engine[dev]'
```

---

## 1. config 작성

`config/self.yaml` 을 복사해 고객용 config를 만들고 `customer`/`region` 등을 채웁니다.
```bash
cp config/self.yaml config/<고객명>.yaml     # 예: config/acme.yaml
```
최소로 수정할 항목:
```yaml
customer: acme          # 스택 접두어(Lp2ps-acme-*). 소문자와 숫자만.
region: us-west-2       # 배포 리전
cross_account: false    # 단일 계정 분석은 false (다계정은 4단계 참고)
accounts: [self]
provisioning:
  idc_region: us-east-1        # IdC(Identity Center) 리전. IdC 를 안 쓰면 "" 로 비워도 된다.
  uses_identity_center: true   # IdC 를 쓰지 않으면 false — 승인 시 나오는 산출물이 달라진다
                               #  true  → Permission Set .tf + 관리형 IAM 정책·역할 .tf + 정책 JSON
                               #  false → 관리형 IAM 정책·역할 .tf + 정책 JSON (PS 는 apply 할 IdC 가 없다)
```
검증:
```bash
engine/.venv/bin/python -m lp2ps.cli validate-config -c config/acme.yaml
```

---

## 2. 원클릭 배포

```bash
# 첫 계정 (해당 계정·리전에서 CDK를 처음 쓰는 경우 --bootstrap 추가)
infra/scripts/deploy-all.sh config/acme.yaml --bootstrap

# 이후(이미 bootstrap 된 경우) 또는 재배포
infra/scripts/deploy-all.sh config/acme.yaml
```

스크립트가 아래를 순서대로 자동 실행합니다:
```
[0] cdk bootstrap        (--bootstrap 을 준 경우에만)
[1] engine·API 에셋 빌드
[2] Data, Auth, Engine, Api 배포
[3] web 빌드 (API 주소 자동 주입)
[4] Web 배포
[5] CORS origin 잠금 (CloudFront 도메인을 API에 주입 + API GW 스테이지 갱신)
```
완료되면 마지막에 다음이 출력됩니다:
```
✅ DEPLOY-ALL complete (Lp2ps-acme)
   Web dashboard : https://xxxxx.cloudfront.net
   API           : https://xxxxx.execute-api...
   Cognito pool  : us-west-2_XXXXXXXXX
```
→ **웹 대시보드 URL**과 **Cognito 풀 ID**를 적어두세요(다음 단계에서 필요).

> 5~10분 걸립니다. 코드나 config를 변경한 뒤에는 이 스크립트를 다시 실행하면 에셋이 자동으로 재빌드됩니다.

---

## 3. 웹 로그인 사용자 생성 + 로그인

웹 앱은 로그인이 필요합니다. 자체 가입(self sign-up)은 비활성이므로 관리자가 사용자를 초대합니다.

> ⚠ **먼저 콘솔 리전을 맞추세요.** 우측 상단 리전 선택기를 배포한 `region:` 으로 바꿉니다. 사용자 풀은
> 그 리전에만 존재하므로, 다른 리전에서는 **User pools** 목록이 비어 보이고 실수로 *새* 풀을 만들기
> 시작하게 됩니다("Define your application" → Traditional web application / SPA / … 화면).
> **새 풀을 만들지 마세요.** 풀은 `<prefix>-Auth` 스택이 이미 만들었고, 여기서는 사용자만 추가합니다.

1. AWS 콘솔에서 **"Cognito"** 검색 → **Amazon Cognito** → **User pools**
2. 2단계의 **Cognito 풀 ID**와 일치하는 풀 클릭 → **Users** 탭 → **Create user**
3. Email address와 Password(12자 이상, 대·소문자·숫자·기호 포함) 입력 → **Create user**
4. **비밀번호를 영구(permanent)로 전환**(필수). 콘솔에서 만든 사용자는 `FORCE_CHANGE_PASSWORD` 상태가
   되는데, 로그인 화면은 "새 비밀번호 필요" 챌린지를 구현하지 않았으므로
   *"Password reset required (contact your administrator)"* 로 실패합니다. 다음을 실행하세요:
   ```bash
   aws cognito-idp admin-set-user-password \
     --user-pool-id <Cognito 풀 ID> --username <이메일> \
     --password '<위와 같은 비밀번호>' --permanent --region <리전>
   ```
   사용자 상태가 `CONFIRMED` 로 바뀝니다. 확인:
   `aws cognito-idp admin-get-user --user-pool-id <풀> --username <이메일> --region <리전> --query UserStatus`
5. 브라우저에서 **웹 대시보드 URL** 열기 → 이 사용자로 로그인
6. 대시보드 상단의 **"Run full scan"** 클릭 → 첫 분석 시작(수 분) → 완료되면 persona와 리포트가 채워집니다

### 승인한 정책을 실제로 반영하기

**Persona 검토** → **정책 편집** → 권한 확인 → **이 정책으로 승인** 하면 **반영 산출물** 창이 열립니다.
필요한 형태만 내려받아 쓰면 됩니다.

| 산출물 | 언제 쓰나 |
|---|---|
| **IAM 정책 (.tf)** | 이미 있는 역할에 최소권한을 붙일 때(가장 흔한 경우). apply 후 나온 정책 ARN 을 역할에 attach |
| **정책 JSON** | 콘솔에서 손으로 기존 정책을 갈아끼울 때 |
| **IAM 역할 (.tf)** | 역할까지 새로 만들 때. `var.<persona>_trusted_principals`(누가 assume 하는가)를 **반드시 채운 뒤** apply |
| **Permission Set (.tf)** | IdC 를 쓸 때만 나옵니다(`uses_identity_center: true`) |

> ⚠ 반영 전에 볼 것: 정책의 `Resource` 는 `"*"` 입니다 — **action 만** 최소화했습니다.
> 그리고 persona 정책은 그 persona **멤버 전원의 실사용 action 합집합**이라, 멤버 한 명에게는
> 필요 이상일 수 있으나 부족하지는 않습니다. 다른 계정에 반영할 때는 **계정마다** apply 하세요.

---

## 4. (선택) 다계정 분석

하나의 도구 계정에서 여러 계정을 분석하려면, 각 멤버 계정에 읽기 전용 role을 배포하고
config를 `cross_account: true` 로 변경합니다. 상세 절차와 제약은 **`docs/multi-account-onboarding.md`** 를 보세요.

요약: 멤버 계정에 `cfn/lp2ps-readonly-role.yaml` 배포 → config에
`cross_account: true`, `accounts: [<계정 ID들>]`, `readonly_role_name: lp2ps-readonly` 설정 →
`infra/scripts/deploy-all.sh config/acme.yaml` 재실행.

> ⚠ **제약**: Permission Set **할당(실제 적용)** 은 대상 계정이 도구 IdC와 **같은 AWS Organization** 에
> 속할 때만 가능합니다. 수집·분석·PS 정의 생성은 Org와 무관하게 동작합니다. (상세는
> `docs/multi-account-onboarding.md` 의 "Scope of application" 절 참고.)

---

## 5. 삭제 (원클릭)

```bash
infra/scripts/destroy-all.sh config/acme.yaml
```
5개 스택을 역순으로 삭제합니다(S3/DynamoDB 데이터 포함). 멤버 계정의 role은 각 멤버 계정에서
`lp2ps-readonly` 스택을 별도로 삭제하세요.

---

## 트러블슈팅 (자주 겪는 문제)

| 증상 | 해결 |
|---|---|
| `aws login required` | `aws sso login --profile <프로필>` 실행 후 재시도 |
| `not bootstrapped` | `--bootstrap` 옵션을 붙여 재실행 |
| `config parse failed` | `customer:` 와 `region:` 이 파일의 맨 왼쪽 열에 있는지 확인 |
| 로그인 시 `Password reset required (contact your administrator).` | 사용자가 아직 `FORCE_CHANGE_PASSWORD` 상태 → 3-4의 `admin-set-user-password --permanent` 실행 |
| Cognito 콘솔에 **User pools** 목록이 비어 있음 | 리전이 다름. 콘솔 우측 상단 리전을 `region:` 으로 변경. 새 풀을 만들지 말 것 |
| 웹 로그인 후 무한 로딩 | 이 스크립트가 순서를 자동으로 보장하므로 드문 경우입니다. 발생하면 `deploy-all.sh` 재실행 |
| 웹에 예전 화면이 보임 | 브라우저 강제 새로고침(Cmd+Shift+R / Ctrl+Shift+R) |
| Permission denied | 로그인한 role이 Admin인지 확인 |

더 자세한 단계별 설명, 콘솔 클릭 경로, Permission Set 생성, 데이터 소스 비용은
**`docs/deployment-guide.md`** 를 보세요.
