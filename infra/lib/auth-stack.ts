/**
 * auth stack — Cognito user pool + app client.
 *
 * Used by the API GW authorizer (referenced by the API stack). Security: strong password policy +
 * MFA (OPTIONAL; recommend REQUIRED in production) + advanced security. removalPolicy DESTROY since
 * this is a sample.
 */
import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as cognito from "aws-cdk-lib/aws-cognito";
import { NagSuppressions } from "cdk-nag";
import type { Lp2psConfig } from "./config-loader";

export interface AuthStackProps extends cdk.StackProps {
  cfg: Lp2psConfig;
}

export class AuthStack extends cdk.Stack {
  public readonly userPool: cognito.UserPool;
  public readonly userPoolClient: cognito.UserPoolClient;

  constructor(scope: Construct, id: string, props: AuthStackProps) {
    super(scope, id, props);

    this.userPool = new cognito.UserPool(this, "UserPool", {
      selfSignUpEnabled: false, // admin invite only (control tool access)
      signInAliases: { email: true },
      mfa: cognito.Mfa.OPTIONAL,
      mfaSecondFactor: { sms: false, otp: true },
      passwordPolicy: {
        minLength: 12,
        requireLowercase: true,
        requireUppercase: true,
        requireDigits: true,
        requireSymbols: true,
      },
      accountRecovery: cognito.AccountRecovery.EMAIL_ONLY,
      // Threat protection is set via feature plan (advancedSecurityMode is deprecated). Standard tier for the sample.
      featurePlan: cognito.FeaturePlan.ESSENTIALS,
      removalPolicy: cdk.RemovalPolicy.DESTROY,
    });

    this.userPoolClient = this.userPool.addClient("WebClient", {
      authFlows: { userSrp: true },
      preventUserExistenceErrors: true,
      accessTokenValidity: cdk.Duration.hours(1),
      idTokenValidity: cdk.Duration.hours(1),
      // Shortened from the 30-day default to 1 hour to limit refresh-token theft exposure. Tokens are
      // held in memory only on the client (see frontend/src/auth/inMemoryStorage.ts).
      refreshTokenValidity: cdk.Duration.hours(1),
    });

    NagSuppressions.addResourceSuppressions(this.userPool, [
      {
        id: "AwsSolutions-COG2",
        reason: "MFA is OPTIONAL (sample). Documented to raise to REQUIRED for production deployments.",
      },
      {
        id: "AwsSolutions-COG8",
        reason: "The plus tier (threat protection) incurs cost — the sample uses ESSENTIALS. Documented to upgrade to plus in production.",
      },
    ]);

    new cdk.CfnOutput(this, "UserPoolId", { value: this.userPool.userPoolId });
    new cdk.CfnOutput(this, "UserPoolClientId", { value: this.userPoolClient.userPoolClientId });
  }
}
