import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Cf001Adapter } from './cf-001.adapter.js';

const MISSING_VIEWER_CERTIFICATE_FINDING = 'missing-viewer-certificate';
const MISSING_MINIMUM_PROTOCOL_VERSION_FINDING = 'missing-minimum-protocol-version';
const INSECURE_MINIMUM_PROTOCOL_VERSION_FINDING = 'insecure-minimum-protocol-version';
const DEFAULT_CERTIFICATE_FINDING = 'default-certificate-forces-tls-v1';

const FINDINGS = {
  [MISSING_VIEWER_CERTIFICATE_FINDING]: {
    issue: 'CloudFront distribution does not declare any viewer certificate settings, so a minimum TLS version of 1.2 cannot be confirmed.',
    remediation: 'Configure the CloudFront distribution viewer certificate settings to enforce a minimum TLS version of 1.2 or higher.',
  },
  [MISSING_MINIMUM_PROTOCOL_VERSION_FINDING]: {
    issue: 'CloudFront distribution viewer certificate is configured without an explicit minimum TLS protocol version, which allows TLS versions below 1.2.',
    remediation: 'Set the minimum TLS protocol version for the CloudFront distribution viewer certificate to TLS 1.2 or higher.',
  },
  [INSECURE_MINIMUM_PROTOCOL_VERSION_FINDING]: {
    issue: 'CloudFront distribution viewer certificate is configured with a minimum TLS protocol version that cannot be confirmed to enforce TLS 1.2 or higher.',
    remediation: 'Update the CloudFront distribution viewer certificate to use a recognized minimum TLS protocol version of 1.2 or higher.',
  },
  [DEFAULT_CERTIFICATE_FINDING]: {
    issue: 'CloudFront distribution uses the default CloudFront certificate, which forces the security policy to TLSv1 and permits TLS 1.0 and 1.1 regardless of any minimum TLS protocol version configured.',
    remediation: 'Serve this distribution from a domain you control: add an alternate domain name, provision an ACM or IAM certificate covering it, point DNS at the distribution, then set a minimum TLS protocol version of 1.2 or higher. Setting MinimumProtocolVersion while the default certificate is in use has no effect, so no template edit alone resolves this.',
    manualFixRequired: true,
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Cf001Control extends SecurityControl<Cf001Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CF-001',
      priority: 'HIGH',
      description: 'CloudFront distributions must enforce a minimum TLS version of 1.2 for viewer connections',
      findings: FINDINGS,
    });
  }

  /**
   * Checked before MinimumProtocolVersion because CloudFront overrides that value:
   * with CloudFrontDefaultCertificate the security policy is forced to TLSv1
   * "regardless of the value that you specify for MinimumProtocolVersion". A
   * distribution can therefore declare TLSv1.2_2021 and still serve TLS 1.0.
   */
  protected evaluate(adapter: Cf001Adapter): FindingKey | null {
    if (adapter.usesDefaultCloudFrontCertificate()) return DEFAULT_CERTIFICATE_FINDING;
    if (!adapter.hasViewerCertificate()) return MISSING_VIEWER_CERTIFICATE_FINDING;
    if (!adapter.hasMinimumProtocolVersion()) return MISSING_MINIMUM_PROTOCOL_VERSION_FINDING;
    if (adapter.hasInsecureMinimumProtocolVersion()) return INSECURE_MINIMUM_PROTOCOL_VERSION_FINDING;
    return null;
  }
}

export const cf001Control = new Cf001Control();
