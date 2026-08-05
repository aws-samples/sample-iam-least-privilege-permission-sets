/**
 * engine 스택 — 엔진 zip Lambda + Step Functions + read-only role + EventBridge 스케줄.
 *
 * 엔진은 zip 패키징(Docker 없음): 의존성은 Lambda Layer(infra/assets/engine-layer), 코드는
 * infra/assets/engine-code(lp2ps 패키지). boto3 는 런타임 내장. 상승경로는 규칙 기반이라 대형 계정도
 * Lambda 15분 안에 완주(PMapper·Fargate 제거됨).
 *
 * Step Functions: collect→analyze→synth→report 순차(각 stage 는 handler 를 stage 인자로 호출).
 * read-only 엔진 role: 멤버계정 assume + 도구 소유 S3/DynamoDB write. 멤버계정 IAM write 0(불변식①).
 * provisioning(sso-admin)은 opt-in 일 때만 별도 정책(이 스택에선 미부여 — API 스택 전용 role 에서 부여).
 *
 * 사전: `infra/scripts/build-engine-assets.sh` 로 assets 빌드 필요.
 */
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as path from "path";
import * as lambda from "aws-cdk-lib/aws-lambda";
import * as iam from "aws-cdk-lib/aws-iam";
import * as sfn from "aws-cdk-lib/aws-stepfunctions";
import * as tasks from "aws-cdk-lib/aws-stepfunctions-tasks";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import * as logs from "aws-cdk-lib/aws-logs";
import type * as s3 from "aws-cdk-lib/aws-s3";
import type * as kms from "aws-cdk-lib/aws-kms";
import type * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { NagSuppressions } from "cdk-nag";
import type { Lp2psConfig } from "./config-loader";

export interface EngineStackProps extends cdk.StackProps {
  cfg: Lp2psConfig;
  dataBucket: s3.Bucket;
  runsTable: dynamodb.Table;
  metricsTable: dynamodb.Table;
  dataKey: kms.Key; // 로그그룹 CMK 암호화용(DataStack CMK 재사용)
}

const ASSETS = path.join(__dirname, "..", "assets");

export class EngineStack extends cdk.Stack {
  public readonly stateMachine: sfn.StateMachine;
  public readonly scheduleRule: events.Rule;

  constructor(scope: Construct, id: string, props: EngineStackProps) {
    super(scope, id, props);
    const { cfg, dataBucket, runsTable, metricsTable } = props;

    // 읽기전용 엔진 role — 멤버계정 assume + 도구 소유 리소스 write. 멤버계정 IAM write 없음.
    const engineRole = new iam.Role(this, "EngineRole", {
      assumedBy: new iam.ServicePrincipal("lambda.amazonaws.com"),
      description: "LP2PS engine (read-only analysis + tool-owned writes)",
    });
    engineRole.addManagedPolicy(
      iam.ManagedPolicy.fromAwsManagedPolicyName("service-role/AWSLambdaBasicExecutionRole"),
    );
    // 도구 소유 S3/DynamoDB write(산출물). 멤버계정이 아니라 tooling 리소스.
    dataBucket.grantReadWrite(engineRole);
    runsTable.grantReadWriteData(engineRole);
    metricsTable.grantReadWriteData(engineRole);

    // cross_account 이면 멤버계정 readonly role assume 허용(교차계정 수집).
    if (cfg.cross_account && cfg.readonly_role_name) {
      engineRole.addToPolicy(
        new iam.PolicyStatement({
          actions: ["sts:AssumeRole"],
          resources: cfg.accounts.map(
            (acct) => `arn:aws:iam::${acct}:role/${cfg.readonly_role_name}`,
          ),
        }),
      );
    }
    // 자기 계정(cross_account=false) ambient 읽기용 조회 권한. 엔진 awsguard 가 런타임 verb 강제.
    engineRole.addToPolicy(
      new iam.PolicyStatement({
        sid: "ReadOnlyInventory",
        actions: [
          "iam:GetAccountAuthorizationDetails",
          "iam:GenerateCredentialReport",
          "iam:GetCredentialReport",
          "iam:GenerateServiceLastAccessedDetails",
          "iam:GetServiceLastAccessedDetails",
          "access-analyzer:ListAnalyzers",
          "access-analyzer:ListFindingsV2",
          "cloudtrail:LookupEvents", // CloudTrail Lake 미사용 — 기본 LookupEvents 만(무료).
          // IdC(sso-admin) Permission Set 할당 조회 — sso_ps 수집(마이그레이션 스냅샷 비율).
          "sso:ListInstances",
          "sso:ListPermissionSets",
          "sso:ListAccountAssignments",
          "sso:DescribePermissionSet",
          "sts:GetCallerIdentity",
        ],
        resources: ["*"], // 조회 API 는 리소스 스코핑 제한적 — awsguard 훅이 verb 를 강제
      }),
    );

    const depsLayer = new lambda.LayerVersion(this, "EngineDepsLayer", {
      code: lambda.Code.fromAsset(path.join(ASSETS, "engine-layer")),
      compatibleRuntimes: [lambda.Runtime.PYTHON_3_12],
      description: "LP2PS engine deps (pyarrow, pydantic, jinja2, pyyaml)",
    });

    // EngineFn 로그그룹을 명시 생성(retention + CMK). 암시적 그룹은 retention 없음(무기한).
    // 엔진 로그엔 계정ID·ARN 등이 섞일 수 있어 CMK 암호화(키정책은 CWL 서비스 principal 이미 허용).
    const engineFnLogs = new logs.LogGroup(this, "EngineFnLogs", {
      retention: logs.RetentionDays.THREE_MONTHS,
      encryptionKey: props.dataKey,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    const engineFn = new lambda.Function(this, "EngineFn", {
      runtime: lambda.Runtime.PYTHON_3_12,
      handler: "lp2ps.handler.handler",
      code: lambda.Code.fromAsset(path.join(ASSETS, "engine-code")),
      layers: [depsLayer],
      role: engineRole,
      logGroup: engineFnLogs,
      timeout: cdk.Duration.minutes(15), // 명시적(보안 요건)
      memorySize: 3008, // 명시적 — 정규화/parquet 여유
      ephemeralStorageSize: cdk.Size.mebibytes(2048),
      environment: {
        LP2PS_OUT: `s3://${dataBucket.bucketName}`,
        LP2PS_CONFIG_INLINE: JSON.stringify(cfg),
        LP2PS_RUNS_TABLE: runsTable.tableName,
        LP2PS_METRICS_TABLE: metricsTable.tableName,
        // 엔진의 S3 산출물 쓰기도 ExpectedBucketOwner + SSE-KMS(fail-closed)를 쓴다.
        // 이 env 가 없으면 storage._put 이 무암호 저장을 거부하므로 반드시 주입한다.
        LP2PS_EXPECTED_BUCKET_OWNER: this.account,
        LP2PS_DATA_KEY_ARN: dataBucket.encryptionKey?.keyArn ?? "",
      },
    });

    // Step Functions: collect → analyze → synth → report(각 stage 는 handler 를 stage 로 호출).
    const stage = (name: string): tasks.LambdaInvoke =>
      new tasks.LambdaInvoke(this, `Stage-${name}`, {
        lambdaFunction: engineFn,
        payload: sfn.TaskInput.fromObject({
          stage: name,
          "run_id.$": "$.run_id",
          "started_at.$": "$.started_at",
        }),
        resultPath: `$.${name}Result`,
      });

    const definition = stage("collect")
      .next(stage("analyze"))
      .next(stage("synth"))
      .next(stage("report"));

    // 로그그룹을 DataStack CMK 로 암호화. CloudWatch Logs 서비스가 이 계정·리전의 로그그룹을
    // 암호화할 수 있도록 키정책에 logs.<region>.amazonaws.com 권한(+SourceArn 조건)을 추가한다.
    props.dataKey.addToResourcePolicy(
      new iam.PolicyStatement({
        sid: "AllowCloudWatchLogs",
        principals: [new iam.ServicePrincipal(`logs.${this.region}.amazonaws.com`)],
        actions: ["kms:Encrypt*", "kms:Decrypt*", "kms:ReEncrypt*", "kms:GenerateDataKey*", "kms:Describe*"],
        resources: ["*"],
        conditions: {
          ArnLike: { "kms:EncryptionContext:aws:logs:arn": `arn:aws:logs:${this.region}:${this.account}:log-group:*` },
        },
      }),
    );
    const pipelineLogs = new logs.LogGroup(this, "PipelineLogs", {
      retention: logs.RetentionDays.THREE_MONTHS, // 30일 → ≥90일
      encryptionKey: props.dataKey, //
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      // 파이프라인 로그(cross-account STS·IAM 데이터)에도 민감 데이터 마스킹.
      // CMK 암호화와 DataProtectionPolicy 는 독립 레이어라 공존한다(배포 검증 대상).
      //(redaction drift): API 로그군과 동일한 4종 식별자로 통일(PHONENUMBER_US 누락 보완).
      dataProtectionPolicy: new logs.DataProtectionPolicy({
        name: "lp2ps-pipeline-log-pii-masking",
        identifiers: [
          logs.DataIdentifier.EMAILADDRESS,
          logs.DataIdentifier.PHONENUMBER_US,
          logs.DataIdentifier.AWSSECRETKEY,
          logs.DataIdentifier.CREDITCARDNUMBER,
        ],
      }),
    });
    this.stateMachine = new sfn.StateMachine(this, "Pipeline", {
      definitionBody: sfn.DefinitionBody.fromChainable(definition),
      timeout: cdk.Duration.hours(1),
      tracingEnabled: true,
      logs: {
        destination: pipelineLogs,
        // LogLevel.ALL 은 state 입출력 페이로드(cross-account STS/credential report 포함)를
        // 전부 기록한다 → ERROR 로 낮춰 실패 시에만 최소 기록. (디버깅 필요 시 비-prod 게이트로만 ALL)
        level: sfn.LogLevel.ERROR,
      },
    });

    // EventBridge 스케줄 — 규칙을 **항상** 생성하고(안정된 이름), API 가 런타임에 cron·활성상태를
    // 조정한다(PUT /schedule). config.schedule.cron 이 있으면 그 값으로 활성 시작, 없으면 무해한
    // 기본 cron 으로 비활성 생성(활성화 전엔 실행되지 않음). run_id=null → 엔진이 새 run 컨텍스트 생성.
    this.scheduleRule = new events.Rule(this, "Schedule", {
      ruleName: `lp2ps-${cfg.customer}-scan-schedule`,
      description: "LP2PS 주기적 전체 조회 실행(대시보드에서 관리)",
      schedule: events.Schedule.expression(`cron(${cfg.schedule.cron ?? "0 2 * * ? *"})`),
      enabled: Boolean(cfg.schedule.cron),
      targets: [
        new targets.SfnStateMachine(this.stateMachine, {
          input: events.RuleTargetInput.fromObject({ run_id: null, started_at: null }),
        }),
      ],
    });

    NagSuppressions.addStackSuppressions(this, [
      {
        id: "AwsSolutions-IAM5",
        reason:
          "읽기 전용 조회 API(GetAccountAuthorizationDetails 등)는 리소스 스코핑이 제한적. " +
          "런타임에 awsguard before-call 훅이 allowlist verb 를 강제한다(불변식①).",
      },
      {
        id: "AwsSolutions-IAM4",
        reason: "AWSLambdaBasicExecutionRole 은 로그 write 전용 관리형 정책(최소 권한).",
      },
      {
        id: "AwsSolutions-L1",
        reason:
          "런타임을 Python 3.12 로 고정 — 엔진 의존성(pyarrow/pydantic) Linux 휠을 3.12 로 빌드해 " +
          "레이어에 넣는다. 최신 런타임 자동 추종은 휠 ABI 불일치를 유발하므로 명시 고정.",
      },
      {
        id: "AwsSolutions-SF1",
        reason:
          "(debug_logging_in_production) 조치로 LogLevel.ALL→ERROR 로 낮췄다. ALL 은 state " +
          "입출력 페이로드(cross-account STS 자격증명·IAM credential report)를 전부 로그에 남겨 " +
          "민감정보 노출 위험이 크다. cdk-nag SF1 은 ALL 을 권장하지만, 이 파이프라인은 민감 페이로드를 " +
          "다루므로 보안 검토 결과를 우선해 ERROR(실패 시에만 기록)로 유지한다. 로그그룹은 CMK 암호화.",
      },
    ]);

    new cdk.CfnOutput(this, "StateMachineArn", { value: this.stateMachine.stateMachineArn });
    new cdk.CfnOutput(this, "EngineFnName", { value: engineFn.functionName });
    new cdk.CfnOutput(this, "ScheduleRuleName", { value: this.scheduleRule.ruleName });
  }
}
