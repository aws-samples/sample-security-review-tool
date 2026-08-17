import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Cf005Adapter, CustomOriginInspection } from './cf-005.adapter.js';

const HTTP_ONLY_POLICY = 'http-only';
const MATCH_VIEWER_POLICY = 'match-viewer';
const LEGACY_SSL_PROTOCOLS: ReadonlySet<string> = new Set(['SSLv3', 'TLSv1', 'TLSv1.1']);

const HTTP_ONLY_FINDING = 'custom-origin-http-only';
const MATCH_VIEWER_FINDING = 'custom-origin-match-viewer';
const LEGACY_SSL_PROTOCOL_FINDING = 'custom-origin-legacy-ssl-protocol';
const MISSING_SSL_PROTOCOLS_FINDING = 'custom-origin-missing-ssl-protocols';

const FINDINGS = {
  [HTTP_ONLY_FINDING]: {
    issue: 'A CloudFront custom origin is configured to connect to the origin over HTTP only, sending traffic in plaintext.',
    remediation: 'Configure the CloudFront custom origin to connect to the origin using HTTPS so that traffic between CloudFront and the origin is encrypted in transit.',
  },
  [MATCH_VIEWER_FINDING]: {
    issue: 'A CloudFront custom origin mirrors the viewer protocol, allowing plaintext HTTP connections to the origin whenever a viewer uses HTTP.',
    remediation: 'Configure the CloudFront custom origin to always connect to the origin over HTTPS, independent of the viewer protocol, so that origin traffic is guaranteed to be encrypted regardless of how viewers connect.',
  },
  [LEGACY_SSL_PROTOCOL_FINDING]: {
    issue: 'A CloudFront custom origin permits legacy SSL/TLS protocol versions (SSLv3, TLS 1.0, or TLS 1.1) to be negotiated with the origin, weakening transport security.',
    remediation: 'Restrict the CloudFront custom origin allowed SSL/TLS protocol list to modern, secure versions (TLS 1.2 or higher) so that legacy protocols cannot be negotiated with the origin.',
  },
  [MISSING_SSL_PROTOCOLS_FINDING]: {
    issue: 'A CloudFront custom origin does not declare an allowed SSL/TLS protocol list, leaving the minimum TLS version for origin connections unspecified.',
    remediation: 'Explicitly declare the allowed SSL/TLS protocol list for the CloudFront custom origin and restrict it to modern, secure versions (TLS 1.2 or higher) so the minimum TLS floor for origin connections is unambiguous.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Cf005Control extends SecurityControl<Cf005Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CF-005',
      priority: 'HIGH',
      description: 'CloudFront distributions must use HTTPS with a secure TLS version for all custom (non-S3) origin connections.',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Cf005Adapter): FindingKey | null {
    const customOrigins = adapter.getCustomOrigins();
    for (const origin of customOrigins) {
      const finding = this.findingFor(origin);
      if (finding) return finding;
    }
    return null;
  }

  private findingFor(origin: CustomOriginInspection): FindingKey | null {
    if (origin.protocolPolicy === HTTP_ONLY_POLICY) return HTTP_ONLY_FINDING;
    if (origin.protocolPolicy === MATCH_VIEWER_POLICY) return MATCH_VIEWER_FINDING;
    if (origin.sslProtocolsUnresolvable) return null;
    if (this.hasLegacySslProtocol(origin.sslProtocols)) return LEGACY_SSL_PROTOCOL_FINDING;
    if (this.isMissingSslProtocols(origin.sslProtocols)) return MISSING_SSL_PROTOCOLS_FINDING;
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
