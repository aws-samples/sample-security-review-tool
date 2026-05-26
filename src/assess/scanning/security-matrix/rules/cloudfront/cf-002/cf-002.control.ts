import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf002Adapter } from './cf-002.adapter.js';

const MISSING_WEB_ACL_SCENARIO = 'missing-web-acl-association';

export class Cf002Control extends SecurityControl<Cf002Adapter> {
  constructor() {
    super({
      id: 'CF-002',
      priority: 'HIGH',
      description: 'CloudFront distributions require WAF protection',
      remediationScenarios: [
        {
          scenario: MISSING_WEB_ACL_SCENARIO,
          intent: 'Associate an AWS WAF web ACL with the CloudFront distribution to protect it against common web exploits.',
        },
      ],
    });
  }

  protected evaluate(adapter: Cf002Adapter): ControlFinding | null {
    if (adapter.hasWebAclAssociation()) {
      return null;
    }
    return {
      scenario: MISSING_WEB_ACL_SCENARIO,
      issue: 'CloudFront distribution has no WAF web ACL associated, leaving it without firewall protection against common web threats',
    };
  }
}

export const cf002Control = new Cf002Control();
