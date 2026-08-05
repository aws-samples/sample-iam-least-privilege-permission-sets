/**
 * api 스택 — API GW(REST) + FastAPI Lambda(Mangum) + Cognito authorizer.
 *
 * API Lambda role: 도구 소유 S3(read) + DynamoDB(read) + Step Functions(StartExecution),
 * 그리고 tooling 계정 IdC 의 Permission Set **정의** 생성(sso:CreatePermissionSet /
 * PutInlinePolicyToPermissionSet). **멤버계정 assume·IAM write 권한 0.** provision-ps 는 persona 가
 * approved 상태인지 서버에서 확인한 뒤에만 이 write 를 하고(catalog.py), CreateAccountAssignment 등
 * 멤버계정 권한 부여 액션은 role 에 미부여 — 실제 할당은 사람이 수동으로 한다.
 *
 * 인증: API GW Cognito authorizer(1차) + FastAPI auth.py in-process 재검증(2차).
 * 사전: build-engine-assets.sh 로 api-layer/api-code 에셋 빌드 필요.
 */
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as path from "path";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as iam from "aws-cdk-lib/aws-iam";
import * as apigw from "aws-cdk-lib/aws-apigateway";
import * as cognito from "aws-cdk-lib/aws-cognito";
import * as logs from "aws-cdk-lib/aws-logs";
import * as bedrock from "aws-cdk-lib/aws-bedrock";
import type * as s3 from "aws-cdk-lib/aws-s3";
import type * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import type * as sfn from "aws-cdk-lib/aws-stepfunctions";
import type * as events from "aws-cdk-lib/aws-events";
import { NagSuppressions } from "cdk-nag";
import type { Lp2psConfig } from "./config-loader";

export interface ApiStackProps extends cdk.StackProps {
  cfg: Lp2psConfig;
  userPool: cognito.UserPool;
  dataBucket: s3.Bucket;
  runsTable: dynamodb.Table;
  metricsTable: dynamodb.Table;
  catalogTable: dynamodb.Table;
  stateMachine: sfn.StateMachine;
  scheduleRule: events.Rule;
}

const ASSETS = path.join(__dirname, "..", "assets");

export class ApiStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: ApiStackProps) {
    super(scope, id, props);
    const { cfg, userPool, dataBucket, runsTable, metricsTable, catalogTable, stateMachine, scheduleRule } =
      props;

    // CORS 허용 origin 은 CloudFront 도메인만. Web 스택(도메인)은 Api 보다 나중에 배포되어
    // synth 시 도메인을 알 수 없으므로 CfnParameter 로 받는다(2단계: 최초 배포 → 도메인 확인 →
    // 이 파라미터로 재배포). 기본값 "" = 아무 origin 도 허용 안 함(fail-safe, 와일드카드 금지).
    const webOrigin = new cdk.CfnParameter(this, "WebOrigin", {
      type: "String",
      default: "",
      description: "허용할 웹 origin(CloudFront 도메인, 예: https://xxxx.cloudfront.net). 비우면 CORS 닫힘.",
    });
    const allowedOrigins = [webOrigin.valueAsString];

    // Bedrock guardrail for the assistant path. LP2PS feeds the model IAM metadata collected from
    // member accounts -- role, user and policy names it does not control -- so untrusted text
    // reaches an LLM prompt. The app-level harness (structured output + grounding verifier +
    // temperature 0) constrains what the model may *say*; the guardrail is the input-side control.
    //
    // Scope: PROMPT_ATTACK only. No denied-topic policy and no PII entity policy.
    //
    // A denied-topic policy along the lines of "do not recommend granting AdministratorAccess or
    // wildcard actions" is the obvious candidate, and it is left out on three grounds.
    //
    // 1. The threat it targets is already covered elsewhere. What it would guard against is the
    //    model recommending an over-broad grant. That path is closed by design rather than by
    //    filtering: every AI field is advisory-only and namespaced ai_*/ai_suggested (invariant 3),
    //    the deterministic core never imports lp2ps.ai, the grounding verifier rejects output
    //    citing anything outside the collected grounding set, and no assistant output provisions
    //    anything -- Permission Set creation is a separate, explicitly confirmed, approved-persona
    //    path that never assigns accounts. A topic filter would be a second, weaker check on a
    //    decision the model does not get to make.
    // 2. The narrow configuration is sufficient for the input-side risk that does exist. Replaying
    //    the recorded pre-guardrail baseline through the deployed path with PROMPT_ATTACK active
    //    produced no blocks on any of the 20 legitimate queries (assistant_blocked and
    //    assistant_incomplete both absent from the audit log for that window).
    // 3. A topic definition would introduce an unmeasured false-positive risk. It is semantically
    //    adjacent to questions an operator must be able to ask -- "which principals still hold
    //    AdministratorAccess", "which personas have wildcard actions", "grant the broadest
    //    permissions to a new engineer". Those are the tool's purpose, and no measurement of a
    //    deployed topic policy exists, because none has been deployed.
    //
    // On where untrusted text actually sits, since it bears on any future topic or PII decision:
    // the context carries aggregates plus closed-taxonomy persona names ("BroadAdminPersona") and
    // expanded action strings rather than policy names or member ARNs; measured on the tooling
    // account's own catalog it contained zero "AdministratorAccess" strings and zero wildcard
    // characters. Read that count narrowly -- it is one catalog. Action strings are copied verbatim
    // from member-account policy documents with no format validation
    // (m2_normalizer._actions_from_document), so a customer granting `iam:*` will have wildcards in
    // this context. What generalizes is the structure, not the counts.
    //
    // If you add a topic or PII policy, replay the baseline first and revisit this comment and the
    // matching assertion in test/api-stack.test.ts deliberately. Twenty queries bound a
    // false-positive rate loosely, and the run-to-run variance in this system sits in the model
    // output and the grounding verifier rather than here.
    //
    // On guardContent (bedrock_client.py): the harness routes untrusted text -- collected action
    // strings and the operator question -- through Converse guardContent blocks. Treat that as
    // narrowing what gets evaluated to the trust boundary, which keeps the trace attributable to a
    // segment and keeps our own instructions from being scanned as override attempts. Do not treat
    // it as a precondition without which the filter is inert; observed behaviour on this API does
    // not support that reading. See lp2ps-finding2-measurements.md.
    const guardrail = new bedrock.CfnGuardrail(this, "AssistantGuardrail", {
      name: `lp2ps-${cfg.customer}-assistant`,
      description:
        "Screens externally-sourced IAM metadata and operator questions on the LP2PS assistant path.",
      // Returned verbatim to the caller as output.message.content[0].text on a block, with
      // stopReason=guardrail_intervened. The app detects the stop reason rather than parsing this.
      blockedInputMessaging:
        "This request was blocked by a safety policy. If it was a legitimate IAM question, rephrase it.",
      blockedOutputsMessaging:
        "The generated response was blocked by a safety policy.",
      contentPolicyConfig: {
        filtersConfig: [
          {
            type: "PROMPT_ATTACK",
            inputStrength: "HIGH",
            // Prompt attack is an input-side filter; the API rejects an output strength for it.
            outputStrength: "NONE",
          },
        ],
      },
    });

    // Guardrails are versioned; Converse requires an explicit version and DRAFT is mutable. Pinning
    // a numbered version means a console edit to the guardrail cannot silently change runtime
    // behaviour -- the stack has to be redeployed for the app to pick it up.
    const guardrailVersion = new bedrock.CfnGuardrailVersion(this, "AssistantGuardrailVersion", {
      guardrailIdentifier: guardrail.attrGuardrailId,
      description: "Pinned version consumed by the assistant Lambda.",
    });

    const depsLayer = new lambda.LayerVersion(this, "ApiDepsLayer", {
      code: lambda.Code.fromAsset(path.join(ASSETS, "api-layer")),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_12],
      description: "LP2PS API deps (fastapi, mangum, pydantic)",
    });

    // 민감 데이터 식별자(이메일·전화·자격증명·신용카드)를 CloudWatch Logs 가 자동 마스킹.
    // 앱은 프롬프트를 로깅하지 않고 _mask_pii 하지만, 사고성 로깅에 대한 심층 방어(GenAI 서비스 요구).
    const logPiiIdentifiers = [
      logs.DataIdentifier.EMAILADDRESS,
      logs.DataIdentifier.PHONENUMBER_US,
      logs.DataIdentifier.AWSSECRETKEY,
      logs.DataIdentifier.CREDITCARDNUMBER,
    ];
    const mkPiiPolicy = (name: string) =>
      new logs.DataProtectionPolicy({ name, identifiers: logPiiIdentifiers });

    // API Lambda 의 로그그룹을 명시 생성해 DataProtectionPolicy 를 붙인다(암시적 그룹엔 정책 불가).
    // LLM 프롬프트/응답이 흐르는 함수라 이 그룹이 의 핵심 대상.
    const apiFnLogs = new logs.LogGroup(this, "ApiFnLogs", {
      retention: logs.RetentionDays.THREE_MONTHS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      dataProtectionPolicy: mkPiiPolicy("lp2ps-apifn-log-pii-masking"),
    });

    const apiFn = new lambda.Function(this, "ApiFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "lp2ps_api.app.handler",
      code: lambda.Code.fromAsset(path.join(ASSETS, "api-code")),
      layers: [depsLayer],
      logGroup: apiFnLogs,
      timeout: cdk.Duration.seconds(30),
      memorySize: 512,
      environment: {
        LP2PS_CUSTOMER: cfg.customer,
        LP2PS_DATA_BUCKET: dataBucket.bucketName,
        LP2PS_RUNS_TABLE: runsTable.tableName,
        LP2PS_METRICS_TABLE: metricsTable.tableName,
        LP2PS_CATALOG_TABLE: catalogTable.tableName,
        LP2PS_STATE_MACHINE_ARN: stateMachine.stateMachineArn,
        LP2PS_SCHEDULE_RULE_NAME: scheduleRule.ruleName,
        LP2PS_TOOLING_ACCOUNT: this.account, // 관제 계정 식별(계정 목록에서 is_tooling 표기)
        LP2PS_CONFIG_INLINE: JSON.stringify(cfg),
        // 백엔드 CORSMiddleware 가 쓰는 허용 origin(파라미터 주입). 비면 CORS 닫힘.
        LP2PS_WEB_ORIGIN: webOrigin.valueAsString,
        // S3 ExpectedBucketOwner = 이 스택 계정(버킷명과 다른 소스).
        LP2PS_EXPECTED_BUCKET_OWNER: this.account,
        // S3 put SSE-KMS 키(데이터 버킷 CMK ARN).
        LP2PS_DATA_KEY_ARN: dataBucket.encryptionKey?.keyArn ?? "",
        // 가드레일 식별자·버전. 앱은 **호출 시점에** 이 값을 읽는다(import 시 고정 금지) — 값이
        // 비어 있으면 guardrailConfig 없이 호출(비활성). 둘 다 있어야 적용된다.
        LP2PS_GUARDRAIL_ID: guardrail.attrGuardrailId,
        LP2PS_GUARDRAIL_VERSION: guardrailVersion.attrVersion,
      },
    });

    // 읽기 권한(도구 소유). 멤버계정 접근·IAM write 없음.
    dataBucket.grantRead(apiFn);
    runsTable.grantReadData(apiFn);
    metricsTable.grantReadData(apiFn);
    catalogTable.grantReadWriteData(apiFn); // PATCH/approve 는 catalog 조정(도구 DynamoDB만)
    stateMachine.grantStartExecution(apiFn); // POST /runs 트리거

    // 스케줄 관리(GET/PUT /schedule) — 도구 소유 EventBridge 규칙 하나만. describe/put 로 cron·
    // 활성상태 조정. 규칙 타깃 배선은 배포 시 고정 — API 는 규칙 정의만 수정(멤버계정 무관).
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ManageScanSchedule",
        // EnableRule/DisableRule 제거 — put_rule 이 State 를 인라인 설정하므로 미사용.
        actions: ["events:DescribeRule", "events:PutRule"],
        resources: [scheduleRule.ruleArn],
      }),
    );

    // AI 개입 기능 런타임 토글 상태(SSM). 대시보드에서 켜고 끄므로 배포 시 ai.enabled 와 무관하게
    // 읽기/쓰기 권한을 부여한다(스코프: 이 customer 의 ai_enabled 파라미터 하나).
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "ManageAiToggle",
        actions: ["ssm:GetParameter", "ssm:PutParameter"],
        resources: [
          `arn:aws:ssm:${this.region}:${this.account}:parameter/lp2ps/${cfg.customer}/ai_enabled`,
        ],
      }),
    );

    // AI 하네스 — Bedrock 모델 호출. 런타임 토글로 켤 수 있으므로 배포 시 ai.enabled 여부와
    // 무관하게 권한 부여(실제 호출 여부는 SSM 토글 + 앱 레벨 grounding gate 가 통제).
    // Bedrock 은 이 config 의 모델 + 리전 inference-profile 로 리소스를 좁힌다(와일드카드 제거).
    const bedrockModel = cfg.ai.model || "us.anthropic.claude-haiku-4-5-20251001-v1:0";
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "BedrockInvoke",
        // **Converse API 는 `bedrock:InvokeModel` 로 인가된다** — 호출하는 API 이름과 인가에
        // 쓰이는 IAM 액션이 다르다. 과거 이 statement 는 "하네스는 Converse 만 쓴다"는 이유로
        // InvokeModel 을 빼고 `bedrock:Converse` 만 두었는데, 그러면 어시스턴트가 완전히
        // 동작하지 않는다. 최소권한 의도는 옳았고 Bedrock 의 인가 모델을 잘못 읽은 것이다.
        //   실측(CloudTrail): eventName=Converse → errorCode=AccessDenied,
        //   "not authorized to perform: bedrock:InvokeModel on resource:
        //    arn:aws:bedrock:<region>:<account>:inference-profile/<model>"
        //   → 배포 후 89일 동안 이 role 의 Bedrock 성공 호출이 0건이었다.
        //   앱은 예외를 안전 미응답으로 degrade 하므로(assistant.py) 조용히 죽어 있었다.
        // `bedrock:Converse` 는 정책 문자열로는 허용되지만 인가 판정에 쓰이지 않는 죽은 액션이라
        // **넣지 않는다** — 공개 샘플이므로 복사해 쓰는 사람이 잘못 배우면 안 된다.
        // https://docs.aws.amazon.com/bedrock/latest/userguide/conversation-inference.html
        actions: ["bedrock:InvokeModel"],
        resources: [
          // 온디맨드 foundation model + us. 추론 프로파일(둘 다 있어야 Converse 가 동작).
          `arn:aws:bedrock:${this.region}::foundation-model/*`,
          `arn:aws:bedrock:${this.region}:${this.account}:inference-profile/${bedrockModel}`,
          `arn:aws:bedrock:*::foundation-model/${bedrockModel.replace(/^us\./, "")}`,
        ],
      }),
    );

    // Applying a guardrail is authorized separately from invoking the model, and on a different
    // resource (the guardrail, not the model), so it is a separate statement rather than extra
    // actions on BedrockInvoke. Without this the Converse call fails AccessDenied once
    // guardrailConfig is attached -- i.e. adding the guardrail without this permission would take
    // the assistant down, the same failure mode as the InvokeModel defect above.
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "BedrockApplyGuardrail",
        actions: ["bedrock:ApplyGuardrail"],
        resources: [guardrail.attrGuardrailArn],
      }),
    );

    // provision-ps 완화 예외 — tooling IdC 에 PS '정의'만 생성(account assignment 없음). UI 2차+최종
    // 확인이 런타임 게이트. IdC 인스턴스는 런타임 자동 조회(ListInstances). CreateAccountAssignment 등
    // 멤버계정 권한 부여 액션은 **의도적으로 미부여**(불변식① — 사람 수동).
    // 리소스를 IdC 인스턴스/permission-set ARN prefix 로 좁힌다. instance id 는 런타임에만
    // 알 수 있으므로 ssoins-* 와일드카드(계정·서비스 내). ListInstances 는 리소스 스코핑 미지원이라 분리.
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "IdCListInstances",
        actions: ["sso:ListInstances"],
        resources: ["*"], // ListInstances 는 리소스 레벨 조건 미지원(AWS)
      }),
    );
    apiFn.addToRolePolicy(
      new iam.PolicyStatement({
        sid: "IdCPermissionSetDefinition",
        actions: [
          "sso:CreatePermissionSet",
          "sso:PutInlinePolicyToPermissionSet",
          "sso:ListPermissionSets",
          "sso:DescribePermissionSet",
          "sso:TagResource",
        ],
        resources: [
          "arn:aws:sso:::instance/ssoins-*",
          "arn:aws:sso:::permissionSet/ssoins-*/*",
        ],
      }),
    );

    // Cognito authorizer.
    const authorizer = new apigw.CognitoUserPoolsAuthorizer(this, "Authorizer", {
      cognitoUserPools: [userPool],
    });

    const accessLogs = new logs.LogGroup(this, "ApiAccessLogs", {
      retention: logs.RetentionDays.THREE_MONTHS, // 30일 → ≥90일
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      dataProtectionPolicy: mkPiiPolicy("lp2ps-apiaccess-log-pii-masking"), //
    });

    const api = new apigw.LambdaRestApi(this, "RestApi", {
      handler: apiFn,
      proxy: true,
      defaultMethodOptions: {
        authorizer,
        authorizationType: apigw.AuthorizationType.COGNITO,
      },
      // CORS: 브라우저 preflight(OPTIONS)는 인증 없이 통과해야 한다(Authorization 헤더가 붙는
      // 비단순 요청이라 preflight 발생). 허용 origin 은 CloudFront 도메인(WebOrigin 파라미터)만 —
      // 와일드카드 금지. allowMethods 는 실제 사용 메서드로 축소.
      defaultCorsPreflightOptions: {
        allowOrigins: allowedOrigins,
        // PUT 포함 — /settings/ai·/schedule 이 PUT(누락 시 preflight 차단으로 저장 실패).
        allowMethods: ["GET", "POST", "PUT", "PATCH", "OPTIONS"],
        allowHeaders: ["Content-Type", "Authorization"],
      },
      deployOptions: {
        stageName: "prod",
        accessLogDestination: new apigw.LogGroupLogDestination(accessLogs),
        accessLogFormat: apigw.AccessLogFormat.jsonWithStandardFields(),
        loggingLevel: apigw.MethodLoggingLevel.INFO,
        metricsEnabled: true,
        // 계정 전역 기본값에 의존하지 않고 스테이지 throttling 명시(남용·비용 폭주 방어).
        throttlingRateLimit: 50,
        throttlingBurstLimit: 100,
      },
    });

    NagSuppressions.addStackSuppressions(this, [
      {
        id: "AwsSolutions-L1",
        reason:
          "런타임을 Python 3.12 로 고정 — API 의존성(fastapi/mangum/pydantic) Linux 휠을 3.12 로 " +
          "빌드해 레이어에 넣는다(엔진 스택과 동일 정책).",
      },
      {
        id: "AwsSolutions-IAM4",
        appliesTo: [
          "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
          "Policy::arn:<AWS::Partition>:iam::aws:policy/service-role/AmazonAPIGatewayPushToCloudWatchLogs",
        ],
        reason: "Lambda 기본 실행·API GW CloudWatch 로깅 관리형 정책은 로그 write 전용(표준·최소 권한).",
      },
      {
        id: "AwsSolutions-IAM5",
        reason:
          "잔여 와일드카드 근거( 로 Bedrock·PermissionSet 은 ARN 스코핑 완료): " +
          "(1) grantRead/grantReadData 는 도구 소유 버킷/테이블 스코프 내(CDK grant). " +
          "(2) sso:ListInstances 는 AWS 가 리소스 레벨 조건을 지원하지 않는 계정 전역 조회라 '*' 불가피 " +
          "(별도 statement 로 분리, write 아님). bedrock·CreatePermissionSet 등 나머지는 리소스 ARN 으로 좁혔다.",
      },
      {
        id: "AwsSolutions-APIG4",
        reason: "프록시 통합의 개별 메서드는 defaultMethodOptions 로 Cognito authorizer 적용됨.",
      },
      {
        id: "AwsSolutions-COG4",
        reason: "동일 — 모든 메서드에 Cognito authorizer(defaultMethodOptions).",
      },
      {
        id: "AwsSolutions-APIG2",
        reason: "요청 검증은 FastAPI(pydantic)가 앱 레벨에서 수행. API GW 스키마 검증 불필요.",
      },
      {
        id: "AwsSolutions-APIG1",
        reason: "access log 는 prod 스테이지에 활성(accessLogDestination).",
      },
      {
        id: "AwsSolutions-APIG3",
        reason: "샘플 — WAF 는 고객 배포 시 opt-in. 문서화.",
      },
    ]);

    new cdk.CfnOutput(this, "ApiUrl", { value: api.url });
  }
}
