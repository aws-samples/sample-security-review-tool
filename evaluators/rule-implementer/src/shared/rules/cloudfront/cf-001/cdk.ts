import { Stack, StackProps } from 'aws-cdk-lib';
import { CfnDistribution } from 'aws-cdk-lib/aws-cloudfront';
import { Construct } from 'constructs';

/**
 * Fixture stack for rule CF-001: CloudFront distributions must enforce a minimum
 * TLS version of 1.2 for viewer connections.
 *
 * The rule's evaluate() chain returns the FIRST matching finding per resource, so
 * we need a separate distribution per scenario, each crafted to bypass earlier
 * checks while matching its target check.
 *
 * The L2 `cloudfront.Distribution` construct always synthesizes a `ViewerCertificate`
 * block (defaulting to CloudFrontDefaultCertificate=true), which would either skip
 * the rule entirely or prevent us from omitting required sub-properties. We therefore
 * use the L1 `CfnDistribution` construct so we can model each non-compliant shape exactly.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const defaultDistributionConfig = {
      enabled: true,
      defaultCacheBehavior: {
        targetOriginId: 'primary-origin',
        viewerProtocolPolicy: 'redirect-to-https',
        forwardedValues: {
          queryString: false,
        },
      },
      origins: [
        {
          id: 'primary-origin',
          domainName: 'origin.example.com',
          customOriginConfig: {
            originProtocolPolicy: 'https-only',
          },
        },
      ],
    };

    // Scenario 1: missing-viewer-certificate
    // The DistributionConfig has no ViewerCertificate property at all, so the adapter
    // reports that no viewer certificate settings are declared.
    new CfnDistribution(this, 'MissingViewerCertificateDistribution', {
      distributionConfig: {
        ...defaultDistributionConfig,
        comment: 'CF-001 fixture: missing ViewerCertificate block',
        // ViewerCertificate intentionally omitted.
      },
    });

    // Scenario 2: missing-minimum-protocol-version
    // ViewerCertificate is present and does NOT use the default CloudFront certificate
    // (so the early return is bypassed), but the MinimumProtocolVersion is not set.
    // Providing an IamCertificateId without a MinimumProtocolVersion satisfies these
    // conditions while keeping the synthesized template self-consistent.
    new CfnDistribution(this, 'MissingMinimumProtocolVersionDistribution', {
      distributionConfig: {
        ...defaultDistributionConfig,
        aliases: ['cf001-missing-mpv.example.com'],
        comment: 'CF-001 fixture: ViewerCertificate without MinimumProtocolVersion',
        viewerCertificate: {
          iamCertificateId: 'AS1A2B3C4D5EXAMPLE',
          sslSupportMethod: 'sni-only',
          // minimumProtocolVersion intentionally omitted.
        },
      },
    });

    // Scenario 3: insecure-minimum-protocol-version
    // ViewerCertificate is present, is not the default CloudFront cert, and explicitly
    // sets MinimumProtocolVersion to a value below TLS 1.2 (SSLv3).
    new CfnDistribution(this, 'InsecureMinimumProtocolVersionDistribution', {
      distributionConfig: {
        ...defaultDistributionConfig,
        aliases: ['cf001-insecure-mpv.example.com'],
        comment: 'CF-001 fixture: ViewerCertificate with insecure MinimumProtocolVersion',
        viewerCertificate: {
          iamCertificateId: 'AS1A2B3C4D5EXAMPLE',
          sslSupportMethod: 'sni-only',
          minimumProtocolVersion: 'SSLv3',
        },
      },
    });
  }
}
