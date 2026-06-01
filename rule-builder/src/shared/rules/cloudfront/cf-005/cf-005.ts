import { Stack, StackProps } from 'aws-cdk-lib';
import * as cloudfront from 'aws-cdk-lib/aws-cloudfront';
import * as origins from 'aws-cdk-lib/aws-cloudfront-origins';
import { Construct } from 'constructs';

/**
 * Fixture stack for CF-005.
 *
 * The control inspects each CloudFront custom (non-S3) origin and emits a
 * finding on the FIRST matching condition per origin in this order:
 *   1. protocolPolicy === 'http-only'                  -> custom-origin-http-only
 *   2. protocolPolicy === 'match-viewer'               -> custom-origin-match-viewer
 *   3. legacy SSL protocol present (SSLv3/TLSv1/TLSv1.1) -> custom-origin-legacy-ssl-protocol
 *   4. originSslProtocols missing or empty             -> custom-origin-missing-ssl-protocols
 *
 * Because evaluate() returns on the first matching origin, we use one
 * CloudFront distribution per scenario, each with a single non-compliant
 * custom origin tailored to that scenario.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // ---------------------------------------------------------------------
    // Scenario 1: custom-origin-http-only
    // OriginProtocolPolicy = 'http-only'
    // ---------------------------------------------------------------------
    new cloudfront.Distribution(this, 'HttpOnlyDistribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('http-only.example.com', {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTP_ONLY,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
    });

    // ---------------------------------------------------------------------
    // Scenario 2: custom-origin-match-viewer
    // OriginProtocolPolicy = 'match-viewer'
    // ---------------------------------------------------------------------
    new cloudfront.Distribution(this, 'MatchViewerDistribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('match-viewer.example.com', {
          protocolPolicy: cloudfront.OriginProtocolPolicy.MATCH_VIEWER,
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
    });

    // ---------------------------------------------------------------------
    // Scenario 3: custom-origin-legacy-ssl-protocol
    // OriginProtocolPolicy = 'https-only' with a legacy TLS protocol
    // (TLSv1) included in OriginSSLProtocols.
    // ---------------------------------------------------------------------
    new cloudfront.Distribution(this, 'LegacySslDistribution', {
      defaultBehavior: {
        origin: new origins.HttpOrigin('legacy-ssl.example.com', {
          protocolPolicy: cloudfront.OriginProtocolPolicy.HTTPS_ONLY,
          originSslProtocols: [
            cloudfront.OriginSslPolicy.TLS_V1,
            cloudfront.OriginSslPolicy.TLS_V1_2,
          ],
        }),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.REDIRECT_TO_HTTPS,
      },
    });

    // ---------------------------------------------------------------------
    // Scenario 4: custom-origin-missing-ssl-protocols
    // OriginProtocolPolicy = 'https-only' with OriginSSLProtocols omitted
    // entirely.
    //
    // The L2 HttpOrigin always synthesizes OriginSSLProtocols (defaulting to
    // TLSv1.2 when not specified), so we must drop down to CfnDistribution
    // to faithfully model an origin where the property is absent.
    // ---------------------------------------------------------------------
    new cloudfront.CfnDistribution(this, 'MissingSslProtocolsDistribution', {
      distributionConfig: {
        enabled: true,
        defaultCacheBehavior: {
          targetOriginId: 'missing-ssl-origin',
          viewerProtocolPolicy: 'redirect-to-https',
          forwardedValues: {
            queryString: false,
          },
        },
        origins: [
          {
            id: 'missing-ssl-origin',
            domainName: 'missing-ssl.example.com',
            customOriginConfig: {
              originProtocolPolicy: 'https-only',
              // OriginSSLProtocols intentionally omitted to trigger the
              // custom-origin-missing-ssl-protocols scenario.
            },
          },
        ],
      },
    });
  }
}
