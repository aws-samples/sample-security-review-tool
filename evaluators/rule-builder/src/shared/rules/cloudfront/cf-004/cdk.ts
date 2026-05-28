import { CfnResource, Stack, StackProps } from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import { Construct } from 'constructs';

/**
 * Fixture stack for CF-004: CloudFront distributions must only accept traffic over HTTPS.
 *
 * Triggers all three remediation scenarios:
 *   1. missing-default-viewer-protocol-policy
 *      -> Synthesized via a raw CfnResource so the DefaultCacheBehavior can omit
 *         ViewerProtocolPolicy entirely. Both the L2 Distribution and the L1
 *         CfnDistribution TypeScript types require viewerProtocolPolicy on the
 *         default behavior, so a raw CfnResource is the only way to express the
 *         "missing property" CloudFormation shape without unsafe casts.
 *   2. default-viewer-protocol-policy-allows-http
 *      -> L2 Distribution with default behavior viewerProtocolPolicy = ALLOW_ALL.
 *   3. additional-cache-behavior-allows-http
 *      -> L2 Distribution with a compliant default behavior (REDIRECT_TO_HTTPS)
 *         plus an additional behavior with viewerProtocolPolicy = ALLOW_ALL.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // ---------------------------------------------------------------------
    // Scenario 1: missing-default-viewer-protocol-policy
    // DefaultCacheBehavior with no ViewerProtocolPolicy property.
    // ---------------------------------------------------------------------
    new CfnResource(this, 'MissingViewerProtocolPolicyDistribution', {
      type: 'AWS::CloudFront::Distribution',
      properties: {
        DistributionConfig: {
          Enabled: true,
          DefaultCacheBehavior: {
            TargetOriginId: 'missingPolicyOrigin',
            // Intentionally NO ViewerProtocolPolicy -> triggers scenario 1.
            ForwardedValues: {
              QueryString: false,
            },
          },
          Origins: [
            {
              Id: 'missingPolicyOrigin',
              DomainName: 'origin-missing-policy.example.com',
              CustomOriginConfig: {
                OriginProtocolPolicy: 'https-only',
              },
            },
          ],
        },
      },
    });

    // ---------------------------------------------------------------------
    // Scenario 2: default-viewer-protocol-policy-allows-http
    // L2 Distribution where the default cache behavior explicitly allows HTTP.
    // ---------------------------------------------------------------------
    new cloudfront.Distribution(this, 'DefaultBehaviorAllowsHttpDistribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('origin-default-allow-http.example.com'),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.ALLOW_ALL,
      },
    });

    // ---------------------------------------------------------------------
    // Scenario 3: additional-cache-behavior-allows-http
    // L2 Distribution whose default behavior is compliant (REDIRECT_TO_HTTPS),
    // but an additional behavior allows HTTP traffic.
    // ---------------------------------------------------------------------
    const additionalBehaviorOrigin = new origins.HttpOrigin(
      'origin-additional-allow-http.example.com',
    );
    new cloudfront.Distribution(this, 'AdditionalBehaviorAllowsHttpDistribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('origin-additional-default.example.com'),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
      additionalBehaviors: {
        '/insecure/*': {
          origin: additionalBehaviorOrigin,
          viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.ALLOW_ALL,
        },
      },
    });
  }
}
