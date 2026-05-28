import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Cf006Adapter } from './cf-006.adapter.js';

const SCENARIO_S3_ORIGIN_UNPROTECTED = 's3-origin-without-access-control';
const SCENARIO_NON_S3_OAC_ELIGIBLE_UNPROTECTED = 'non-s3-oac-eligible-origin-without-access-control';

export class Cf006Control extends SecurityControl<Cf006Adapter> {
  constructor() {
    super({
      id: 'CF-006',
      priority: 'HIGH',
      description: 'CloudFront distributions must enable origin access control',
      remediationScenarios: [
        {
          scenario: SCENARIO_S3_ORIGIN_UNPROTECTED,
          intent: 'estrict the S3 origin so the bucket can only be reached through the CloudFront distribution by attaching an origin access control to the distribution origin and granting only that distribution permission to read from the bucket.\n\nWhen introducing additional Lambda functions as part of this fix (for example, any helper or edge functions used by the distribution), ensure each Lambda function is configured with its own dedicated IAM execution role. Do not share a single execution role across multiple Lambda functions — every function must have a 1:1 relationship with its execution role.',
        },
        {
          scenario: SCENARIO_NON_S3_OAC_ELIGIBLE_UNPROTECTED,
          intent: 'Restrict the OAC-eligible origin so it can only be reached through the CloudFront distribution by attaching an origin access control to the distribution origin and configuring the upstream service to only accept signed requests from that distribution.',
        },
      ],
    });
  }

  protected evaluate(adapter: Cf006Adapter): ControlFinding | null {
    if (adapter.unprotectedS3Origins.length > 0) {
      return {
        scenario: SCENARIO_S3_ORIGIN_UNPROTECTED,
        issue: 'CloudFront distribution has an S3 bucket origin that is not restricted by an origin access control or a legacy origin access identity, allowing the bucket to be reached directly without going through the distribution',
      };
    }
    if (adapter.unprotectedOacEligibleOrigins.length > 0) {
      return {
        scenario: SCENARIO_NON_S3_OAC_ELIGIBLE_UNPROTECTED,
        issue: 'CloudFront distribution has an origin that supports origin access control but does not have one attached, allowing the upstream origin to be reached directly without going through the distribution',
      };
    }
    return null;
  }
}

export const cf006Control = new Cf006Control();
