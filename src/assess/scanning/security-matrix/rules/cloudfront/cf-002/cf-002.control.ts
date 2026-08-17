import { SecurityControl } from '../../../controls/security-control.js';
import type { Finding } from '../../../controls/types.js';
import type { Cf002Adapter } from './cf-002.adapter.js';

const MISSING_WEB_ACL_FINDING = 'missing-web-acl-association';

const FINDINGS = {
  [MISSING_WEB_ACL_FINDING]: {
    issue: 'CloudFront distribution has no WAF web ACL associated, leaving it without firewall protection against common web threats',
    remediation: 'Associate an AWS WAF Web ACL with the CloudFront distribution to protect it against common web exploits.\n\nWhen defining the Web ACL, include at least one rule that blocks requests containing Log4j2 JNDI lookup patterns (to mitigate CVE-2021-44228 / Log4Shell). The Web ACL\'s rules collection must be non-empty and contain a rule that inspects request components (such as the URI, query string, headers, and body) for byte-match patterns like "${jndi:" and applies a block action when matched. Alternatively, include the AWS Managed Rule group "AWSManagedRulesKnownBadInputsRuleSet" (which covers the Log4j JNDI signatures) as a rule within the Web ACL.\n\nEnsure each rule has:\n- A unique name and priority.\n- A statement that performs the byte/string match for the JNDI lookup pattern (or references the AWS managed Known Bad Inputs rule group).\n- A block action for custom rules, or "none" override when using the managed rule group so its default block action takes effect.\n- Visibility configuration with metrics and sampled requests enabled.\n\nThen associate this Web ACL with the CloudFront distribution so the distribution is both protected by WAF and shielded from Log4Shell exploitation.',
  },
} as const satisfies Record<string, Finding>;

type FindingKey = keyof typeof FINDINGS;

export class Cf002Control extends SecurityControl<Cf002Adapter, FindingKey> {
  constructor() {
    super({
      id: 'CF-002',
      priority: 'HIGH',
      description: 'CloudFront distributions require WAF protection',
      findings: FINDINGS,
    });
  }

  protected evaluate(adapter: Cf002Adapter): FindingKey | null {
    if (adapter.hasWebAclAssociation()) return null;
    return MISSING_WEB_ACL_FINDING;
  }
}

export const cf002Control = new Cf002Control();
