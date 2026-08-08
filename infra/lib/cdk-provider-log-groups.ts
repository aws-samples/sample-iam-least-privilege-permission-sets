/**
 * Aspect: give CDK-vended custom-resource provider Lambdas a stack-owned log group.
 *
 * Why this exists
 * ---------------
 * `autoDeleteObjects: true` on a bucket makes CDK synthesize a helper Lambda (`Custom::
 * S3AutoDeleteObjectsCustomResourceProvider`). That Lambda gets no `LoggingConfig`, so the Lambda
 * service creates `/aws/lambda/<function-name>` implicitly on first invocation. Nothing in the
 * template owns that log group, so `destroy-all.sh` leaves it behind -- with never-expire retention
 * and no tags tying it to the deployment. Repeated deploy/destroy cycles accumulate orphans in the
 * customer account, which contradicts the teardown section of the deployment guide.
 *
 * `CustomResourceConfig` (aws-cdk-lib/custom-resources) fixes the same problem for constructs whose
 * provider node carries the `...-singleton` / `...-logGroup` / `...-logRetention` metadata -- e.g.
 * `BucketDeployment`. The auto-delete provider only carries `...-customResourceProvider`, which none
 * of those aspects act on, so it is missed. This aspect covers that gap and nothing else: it visits
 * only nodes tagged `CUSTOM_RESOURCE_PROVIDER` and only touches handlers that have no LoggingConfig
 * yet, so it is a no-op the moment CDK starts handling them itself.
 *
 * The provider role has `AWSLambdaBasicExecutionRole`, which permits writing to any log group in the
 * account, so pointing the function at an explicit group needs no extra IAM.
 */
import * as cdk from "aws-cdk-lib";
import { Aspects } from "aws-cdk-lib";
import { CUSTOM_RESOURCE_PROVIDER, CustomResourceConfig } from "aws-cdk-lib/custom-resources";
import * as logs from "aws-cdk-lib/aws-logs";
import type { IAspect } from "aws-cdk-lib";
import type { IConstruct } from "constructs";

/** Log retention for CDK-vended provider log groups -- matched to the app's own log groups. */
const PROVIDER_LOG_RETENTION = logs.RetentionDays.THREE_MONTHS;

/**
 * Make every CDK-vended custom-resource log group stack-owned, so teardown removes it.
 *
 * Applied once to the App (bin/lp2ps.ts). Exported as a function rather than inlined there so the
 * assertions in test/teardown.test.ts exercise the real wiring instead of a copy of it -- the
 * defect this guards against is precisely "the app forgot to apply this".
 *
 * `CustomResourceConfig` covers providers carrying the singleton/logGroup/logRetention metadata
 * (e.g. BucketDeployment); `CdkProviderLogGroups` covers the S3 auto-delete provider, which carries
 * only `...-customResourceProvider` and is therefore missed by the former.
 */
export function applyProviderLogGroupHygiene(app: cdk.App): void {
  CustomResourceConfig.of(app).addLogRetentionLifetime(PROVIDER_LOG_RETENTION);
  CustomResourceConfig.of(app).addRemovalPolicy(cdk.RemovalPolicy.DESTROY);
  Aspects.of(app).add(new CdkProviderLogGroups(PROVIDER_LOG_RETENTION));
}

export class CdkProviderLogGroups implements IAspect {
  constructor(private readonly retention: logs.RetentionDays) {}

  public visit(node: IConstruct): void {
    const isProvider = node.node.metadata.some((m) => m.type === CUSTOM_RESOURCE_PROVIDER);
    if (!isProvider) return;

    // The provider's handler is a raw CfnResource (the provider predates the L2 Function on
    // purpose -- see CustomResourceProvider docs on reverse dependencies), so the log group is
    // wired through a property override rather than a `logGroup` prop.
    const handler = node.node.tryFindChild("Handler") as cdk.CfnResource | undefined;
    if (!handler || handler.cfnResourceType !== "AWS::Lambda::Function") return;
    // Already configured -- either by a newer CDK or by another aspect. Leave it alone.
    if ((handler as unknown as { loggingConfig?: unknown }).loggingConfig) return;
    if (node.node.tryFindChild("LogGroup")) return;

    const logGroup = new logs.LogGroup(node, "LogGroup", {
      retention: this.retention,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });
    handler.addPropertyOverride("LoggingConfig", { LogGroup: logGroup.logGroupName });
  }
}
