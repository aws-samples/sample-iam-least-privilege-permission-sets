/**
 * data 스택 — S3(산출물) + DynamoDB(runs/metrics/catalog/findings).
 *
 * 보안 가드레일(construct 기본값에 박음):
 * - S3: BLOCK_ALL public access + SSE(KMS) + SecureTransport=false deny + server access log
 *        + removalPolicy DESTROY + autoDeleteObjects(샘플이므로)
 * - DynamoDB: 저장 암호화(AWS 관리 KMS), PITR
 * 모든 리소스는 app 레벨 auto-delete=no 태그를 상속(사용자 요청) — removalPolicy 와 별개의 운영 표식.
 */
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import * as kms from "aws-cdk-lib/aws-kms";
import { NagSuppressions } from "cdk-nag";
import type { Lp2psConfig } from "./config-loader";

export interface DataStackProps extends cdk.StackProps {
  cfg: Lp2psConfig;
}

export class DataStack extends cdk.Stack {
  public readonly dataBucket: s3.Bucket;
  public readonly runsTable: dynamodb.Table;
  public readonly metricsTable: dynamodb.Table;
  public readonly catalogTable: dynamodb.Table;
  public readonly findingsTable: dynamodb.Table;
  public readonly dataKey: kms.Key;

  constructor(scope: Construct, id: string, props: DataStackProps) {
    super(scope, id, props);

    // 데이터 버킷 CORS origin 은 CloudFront 도메인만. Web 스택은 이후 배포되므로 synth 시
    // 도메인 미상 → CfnParameter 로 받는다(2단계 배포). 기본 "" = 실제 origin 과 매칭되지 않음
    // (와일드카드 금지 — 빈 문자열 origin 은 어떤 브라우저 origin 과도 안 맞아 사실상 차단).
    const webOrigin = new cdk.CfnParameter(this, "WebOrigin", {
      type: "String",
      default: "",
      description: "데이터 버킷 CORS 허용 origin(CloudFront 도메인). 비우면 매칭되는 origin 없음.",
    });
    const corsOrigins = [webOrigin.valueAsString];

    // 산출물 암호화 키(회전 활성).
    this.dataKey = new kms.Key(this, "DataKey", {
      enableKeyRotation: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY, // 샘플: 정리 용이
      description: "LP2PS data encryption key",
    });

    // S3 access log 버킷(자기 자신 로깅 루프 방지 위해 별도).
    const logBucket = new s3.Bucket(this, "AccessLogBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      versioned: false,
    });
    NagSuppressions.addResourceSuppressions(logBucket, [
      { id: "AwsSolutions-S1", reason: "access log 버킷 자신은 서버 액세스 로그 대상 아님(순환 방지)." },
    ]);

    // 산출물 버킷(raw/iac/reports).
    this.dataBucket = new s3.Bucket(this, "DataBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.KMS,
      encryptionKey: this.dataKey,
      enforceSSL: true, // aws:SecureTransport=false deny 정책 자동 부착
      versioned: true,
      // 버전 관리 버킷의 잔여물 정리 — 이전 버전 90일 후 만료, 미완료 멀티파트 업로드
      // 7일 후 중단(스토리지 누적·비용·오래된 데이터 잔류 방지). 현재 버전 산출물엔 영향 없음.
      lifecycleRules: [
        {
          id: "expire-noncurrent-and-incomplete-uploads",
          noncurrentVersionExpiration: cdk.Duration.days(90),
          abortIncompleteMultipartUploadAfter: cdk.Duration.days(7),
        },
      ],
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      serverAccessLogsBucket: logBucket,
      serverAccessLogsPrefix: "data-access/",
      // 리포트 페이지가 presigned URL 을 fetch→blob 으로 다운로드하려면 CORS 필요.
      // presigned URL 은 서명으로 접근을 제한하므로 CORS origin 은 브라우저 읽기 허용용(GET/HEAD 만).
      cors: [
        {
          allowedMethods: [s3.HttpMethods.GET, s3.HttpMethods.HEAD],
          allowedOrigins: corsOrigins, // CloudFront 도메인(WebOrigin 파라미터)만
          allowedHeaders: ["Content-Type", "Range"], // 필요한 헤더로 축소
          exposedHeaders: ["Content-Length", "Content-Type"],
          maxAge: 3000,
        },
      ],
    });

    // DynamoDB 테이블 4종 — 전부 저장 암호화 + PITR.
    const mkTable = (name: string, pk: string, sk?: string): dynamodb.Table =>
      new dynamodb.Table(this, name, {
        partitionKey: { name: pk, type: dynamodb.AttributeType.STRING },
        sortKey: sk ? { name: sk, type: dynamodb.AttributeType.STRING } : undefined,
        billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
        encryption: dynamodb.TableEncryption.CUSTOMER_MANAGED,
        encryptionKey: this.dataKey,
        pointInTimeRecoverySpecification: { pointInTimeRecoveryEnabled: true },
        removalPolicy: cdk.RemovalPolicy.DESTROY,
      });

    this.runsTable = mkTable("RunsTable", "run_id");
    this.metricsTable = mkTable("MetricsTable", "run_id", "ts");
    this.catalogTable = mkTable("CatalogTable", "persona");
    this.findingsTable = mkTable("FindingsTable", "id");

    new cdk.CfnOutput(this, "DataBucketName", { value: this.dataBucket.bucketName });
    new cdk.CfnOutput(this, "RunsTableName", { value: this.runsTable.tableName });
  }
}
