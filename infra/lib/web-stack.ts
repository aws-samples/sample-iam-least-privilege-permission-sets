/**
 * web 스택 — S3(정적) + CloudFront(OAC) React 호스팅.
 *
 * frontend/dist(사전 빌드)를 S3 에 배포하고 CloudFront OAC 로 서빙한다. SPA 이므로 403/404 를
 * index.html 로 리라이트. 버킷은 BLOCK_ALL(공개 차단) — 오직 CloudFront OAC 만 접근.
 *
 * 사전: frontend 를 실 API/Cognito env 로 빌드(scripts/build-web.sh)해야 dist 가 실배선된다.
 * env 값(API URL·pool ID)은 이미 배포된 api/auth 스택 output 에서 온다.
 */
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as path from "path";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import { NagSuppressions } from "cdk-nag";
import type { Lp2psConfig } from "./config-loader";

export interface WebStackProps extends cdk.StackProps {
  cfg: Lp2psConfig;
  /** Data bucket — only its regional domain is used, to scope the CSP connect-src. */
  dataBucket: s3.IBucket;
}

const DIST = path.join(__dirname, "..", "..", "frontend", "dist");

export class WebStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: WebStackProps) {
    super(scope, id, props);

    const logBucket = new s3.Bucket(this, "WebLogBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      objectOwnership: s3.ObjectOwnership.BUCKET_OWNER_PREFERRED, // CloudFront 로그 write
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
    });
    NagSuppressions.addResourceSuppressions(logBucket, [
      { id: "AwsSolutions-S1", reason: "로그 버킷 자신은 서버 액세스 로그 대상 아님(순환 방지)." },
    ]);

    const siteBucket = new s3.Bucket(this, "SiteBucket", {
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL, // 공개 차단 — OAC 만 접근
      encryption: s3.BucketEncryption.S3_MANAGED,
      enforceSSL: true,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      serverAccessLogsBucket: logBucket,
      serverAccessLogsPrefix: "site-access/",
    });

    // CSP. The SPA only makes XHR calls to the API (execute-api), Cognito (cognito-idp) and the
    // data bucket, so connect-src is limited to those hosts. Inline styles/fonts are allowed
    // (Vite-bundled CSS), img data: allowed, framing denied. The API hostname gets a random
    // subdomain per deployment, hence the wildcard there; the region comes from config.
    //
    // Why the data bucket is in connect-src: report HTML and Terraform downloads fetch the
    // presigned URL into a blob and save it via `a.download`, because the objects are served as
    // text/* and a plain href would make the browser open them in a new tab instead ("download"
    // behaving like "view"). If CSP blocks that fetch the download fails outright.
    //
    // What this does and does not buy us: CSP restricts the connect *host* only. It does not
    // (and cannot) enforce presigning, the account, or the object -- that scoping comes from the
    // presigned URL itself (time-limited, IAM-signed) plus the bucket policy and BLOCK_ALL public
    // access. This directive is defense-in-depth for XHR destinations: default-src stays 'self'
    // and no other directive is relaxed. The host is the bucket's own regional domain (resolved
    // cross-stack via Fn::ImportValue, not a wildcard), so the bucket name is not exposed as a
    // guessable pattern and no other S3 host in the region is reachable.
    //
    // Coupling note: this assumes virtual-hosted-style presigned URLs (bucket in the hostname),
    // which repositories.py pins via addressing_style="virtual". Switching that to path-style
    // would move the bucket into the URL path and break this directive.
    const region = props.cfg.region;
    const csp = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'",
      "img-src 'self' data:",
      "font-src 'self' data:",
      `connect-src 'self' https://*.execute-api.${region}.amazonaws.com https://cognito-idp.${region}.amazonaws.com https://${props.dataBucket.bucketRegionalDomainName}`,
      "frame-ancestors 'none'",
      "base-uri 'self'",
      "object-src 'none'",
    ].join("; ");

    // HSTS(+보안 헤더) 응답 정책. maxAge 2년, includeSubdomains, preload, override.
    const securityHeaders = new cloudfront.ResponseHeadersPolicy(this, "SecurityHeaders", {
      comment: "LP2PS HSTS + 보안 헤더 + CSP",
      securityHeadersBehavior: {
        strictTransportSecurity: {
          accessControlMaxAge: cdk.Duration.days(730), // ≥ 31536000s(1년) — 2년
          includeSubdomains: true,
          preload: true,
          override: true,
        },
        contentTypeOptions: { override: true }, // X-Content-Type-Options: nosniff
        frameOptions: { frameOption: cloudfront.HeadersFrameOption.DENY, override: true },
        referrerPolicy: {
          referrerPolicy: cloudfront.HeadersReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
          override: true,
        },
        contentSecurityPolicy: { contentSecurityPolicy: csp, override: true }, //
      },
    });

    const distribution = new cloudfront.Distribution(this, "Distribution", {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(siteBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
        cachePolicy: cloudfront.CachePolicy.CACHING_OPTIMIZED,
        responseHeadersPolicy: securityHeaders, // 
      },
      defaultRootObject: "index.html",
      // SPA 라우팅: S3 403/404 → index.html(200).
      errorResponses: [
        { httpStatus: 403, responseHttpStatus: 200, responsePagePath: "/index.html" },
        { httpStatus: 404, responseHttpStatus: 200, responsePagePath: "/index.html" },
      ],
      minimumProtocolVersion: cloudfront.SecurityPolicyProtocol.TLS_V1_2_2021,
      enableLogging: true,
      logBucket,
      logFilePrefix: "cf-access/",
      comment: `LP2PS ${props.cfg.customer} web`,
    });

    new s3deploy.BucketDeployment(this, "DeployWeb", {
      sources: [s3deploy.Source.asset(DIST)],
      destinationBucket: siteBucket,
      distribution,
      distributionPaths: ["/*"], // 배포 시 CloudFront 캐시 무효화
    });

    NagSuppressions.addStackSuppressions(this, [
      {
        id: "AwsSolutions-CFR4",
        reason: "TLS 1.2_2021 최소 프로토콜 지정(minimumProtocolVersion). 기본 인증서 사용 샘플.",
      },
      {
        id: "AwsSolutions-CFR1",
        reason: "샘플 — 지리적 제한 없음. 고객 배포 시 필요하면 opt-in.",
      },
      {
        id: "AwsSolutions-CFR2",
        reason: "샘플 — WAF 는 고객 배포 시 opt-in(비용). 문서화.",
      },
      {
        id: "AwsSolutions-L1",
        reason: "BucketDeployment 의 CDK 관리 Lambda 런타임은 CDK 가 관리(사용자 코드 아님).",
      },
      {
        id: "AwsSolutions-IAM4",
        reason: "BucketDeployment CDK 관리 Lambda 의 기본 실행 정책(CDK 내부).",
      },
      {
        id: "AwsSolutions-IAM5",
        reason: "BucketDeployment/autoDelete 의 CDK 관리 role 와일드카드(CDK 내부, 도구 소유 버킷 스코프).",
      },
    ]);

    new cdk.CfnOutput(this, "SiteUrl", { value: `https://${distribution.distributionDomainName}` });
  }
}
