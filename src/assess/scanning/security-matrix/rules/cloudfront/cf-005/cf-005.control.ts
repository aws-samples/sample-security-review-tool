import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf005Adapter, CustomOriginInspection } from './cf-005.adapter.js';

const HTTP_ONLY_POLICY = 'http-only';
const MATCH_VIEWER_POLICY = 'match-viewer';
const LEGACY_SSL_PROTOCOLS: ReadonlySet<string> = new Set(['SSLv3', 'TLSv1', 'TLSv1.1']);

export class Cf005Control extends SecurityControl<Cf005Adapter> {
  constructor() {
    super({
      id: 'CF-005',
      priority: 'HIGH',
      description: 'CloudFront distributions must use HTTPS with a secure TLS version for all custom (non-S3) origin connections.',
      remediationScenarios: [
        {
          scenario: 'custom-origin-http-only',
          intent: 'Configure the CloudFront custom origin to connect to the origin using HTTPS so that traffic between CloudFront and the origin is encrypted in transit.',
        },
        {
          scenario: 'custom-origin-match-viewer',
          intent: 'Configure the CloudFront custom origin to always connect to the origin over HTTPS, independent of the viewer protocol, so that origin traffic is guaranteed to be encrypted regardless of how viewers connect.',
        },
        {
          scenario: 'custom-origin-legacy-ssl-protocol',
          intent: 'Restrict the CloudFront custom origin allowed SSL/TLS protocol list to modern, secure versions (TLS 1.2 or higher) so that legacy protocols cannot be negotiated with the origin.',
        },
        {
          scenario: 'custom-origin-missing-ssl-protocols',
          intent: 'Explicitly declare the allowed SSL/TLS protocol list for the CloudFront custom origin and restrict it to modern, secure versions (TLS 1.2 or higher) so the minimum TLS floor for origin connections is unambiguous.',
        },
      ],
    });
  }

  protected evaluate(adapter: Cf005Adapter): ControlFinding | null {
    const customOrigins = adapter.getCustomOrigins();
    for (const origin of customOrigins) {
      const finding = this.findingFor(origin);
      if (finding) return finding;
    }
    return null;
  }

  private findingFor(origin: CustomOriginInspection): ControlFinding | null {
    if (origin.protocolPolicy === HTTP_ONLY_POLICY) {
      return {
        scenario: 'custom-origin-http-only',
        issue: 'A CloudFront custom origin is configured to connect to the origin over HTTP only, sending traffic in plaintext.',
      };
    }
    if (origin.protocolPolicy === MATCH_VIEWER_POLICY) {
      return {
        scenario: 'custom-origin-match-viewer',
        issue: 'A CloudFront custom origin mirrors the viewer protocol, allowing plaintext HTTP connections to the origin whenever a viewer uses HTTP.',
      };
    }
    if (origin.sslProtocolsUnresolvable) {
      return null;
    }
    if (this.hasLegacySslProtocol(origin.sslProtocols)) {
      return {
        scenario: 'custom-origin-legacy-ssl-protocol',
        issue: 'A CloudFront custom origin permits legacy SSL/TLS protocol versions (SSLv3, TLS 1.0, or TLS 1.1) to be negotiated with the origin, weakening transport security.',
      };
    }
    if (this.isMissingSslProtocols(origin.sslProtocols)) {
      return {
        scenario: 'custom-origin-missing-ssl-protocols',
        issue: 'A CloudFront custom origin does not declare an allowed SSL/TLS protocol list, leaving the minimum TLS version for origin connections unspecified.',
      };
    }
    return null;
  }

  private hasLegacySslProtocol(protocols: readonly string[] | undefined): boolean {
    if (!protocols) return false;
    return protocols.some(protocol => LEGACY_SSL_PROTOCOLS.has(protocol));
  }

  private isMissingSslProtocols(protocols: readonly string[] | undefined): boolean {
    return protocols === undefined || protocols.length === 0;
  }
}

export const cf005Control = new Cf005Control();
