import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf001Adapter } from './cf-001.adapter.js';

const MISSING_VIEWER_CERTIFICATE_SCENARIO = 'missing-viewer-certificate';
const MISSING_MINIMUM_PROTOCOL_VERSION_SCENARIO = 'missing-minimum-protocol-version';
const INSECURE_MINIMUM_PROTOCOL_VERSION_SCENARIO = 'insecure-minimum-protocol-version';

export class Cf001Control extends SecurityControl<Cf001Adapter> {
  constructor() {
    super({
      id: 'CF-001',
      priority: 'HIGH',
      description: 'CloudFront distributions must enforce a minimum TLS version of 1.2 for viewer connections',
      remediationScenarios: [
        {
          scenario: MISSING_VIEWER_CERTIFICATE_SCENARIO,
          intent: 'Configure the CloudFront distribution viewer certificate settings to enforce a minimum TLS version of 1.2 or higher.',
        },
        {
          scenario: MISSING_MINIMUM_PROTOCOL_VERSION_SCENARIO,
          intent: 'Set the minimum TLS protocol version for the CloudFront distribution viewer certificate to TLS 1.2 or higher.',
        },
        {
          scenario: INSECURE_MINIMUM_PROTOCOL_VERSION_SCENARIO,
          intent: 'Update the CloudFront distribution viewer certificate to use a recognized minimum TLS protocol version of 1.2 or higher.',
        },
      ],
    });
  }

  protected evaluate(adapter: Cf001Adapter): ControlFinding | null {
    if (adapter.usesDefaultCloudFrontCertificate()) {
      return null;
    }
    if (!adapter.hasViewerCertificate()) {
      return {
        scenario: MISSING_VIEWER_CERTIFICATE_SCENARIO,
        issue: 'CloudFront distribution does not declare any viewer certificate settings, so a minimum TLS version of 1.2 cannot be confirmed.',
      };
    }
    if (!adapter.hasMinimumProtocolVersion()) {
      return {
        scenario: MISSING_MINIMUM_PROTOCOL_VERSION_SCENARIO,
        issue: 'CloudFront distribution viewer certificate is configured without an explicit minimum TLS protocol version, which allows TLS versions below 1.2.',
      };
    }
    if (adapter.hasInsecureMinimumProtocolVersion()) {
      return {
        scenario: INSECURE_MINIMUM_PROTOCOL_VERSION_SCENARIO,
        issue: 'CloudFront distribution viewer certificate is configured with a minimum TLS protocol version that cannot be confirmed to enforce TLS 1.2 or higher.',
      };
    }
    return null;
  }
}

export const cf001Control = new Cf001Control();
