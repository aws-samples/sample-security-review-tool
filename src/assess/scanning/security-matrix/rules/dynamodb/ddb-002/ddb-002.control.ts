import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Ddb002Adapter } from './ddb-002.adapter.js';

export class Ddb002Control extends SecurityControl<Ddb002Adapter> {
  constructor() {
    super({
      id: 'DDB-002',
      priority: 'HIGH',
      description: 'DynamoDB data plan events must be captured by CloudTrail logging',
      remediationScenarios: [
        {
          scenario: 'no-trail-captures-dynamodb-data-events',
          intent:
            'Add a CloudTrail trail to the template that captures DynamoDB data plane (item-level) events for the offending DynamoDB table. The trail must be actively logging and must include a data event selector whose data resources cover this specific table (or all DynamoDB tables). Do NOT modify the DynamoDB table resource itself — the fix is to introduce CloudTrail (and its supporting resources) into the same template.\n\nWhen introducing supporting resources, every new S3 bucket added by this remediation must satisfy ALL of the following requirements so it does not trigger other security rules:\n\n1. Lifecycle configuration: include at least one lifecycle rule that transitions objects to the STANDARD_IA (infrequent access) storage class after 30 days.\n\n2. Server access logging: configure server access logging by designating a separate log destination bucket. To accomplish this without creating an infinite chain of buckets, introduce TWO S3 buckets:\n   - A primary "trail logs" bucket that stores the CloudTrail logs. This bucket must have server access logging enabled, pointing at the second bucket below as its log destination.\n   - A secondary "access logs" bucket that serves as the server-access-log destination for the primary bucket. Because this secondary bucket is referenced as a log destination by another bucket in the template, it is exempt from the "no server access logging" rule and does NOT itself need server access logging configured. It must still have a lifecycle rule transitioning objects to STANDARD_IA after 30 days.\n\nSummary of required additions:\n1. A CloudTrail trail resource that is enabled/actively logging.\n2. A data event selector on the trail covering the specific DynamoDB table (or all DynamoDB tables) for item-level events.\n3. A primary S3 bucket to receive CloudTrail logs, with (a) a lifecycle rule transitioning objects to STANDARD_IA after 30 days, and (b) server access logging enabled targeting a second bucket.\n4. A secondary S3 bucket that is referenced as the server-access-log destination for the primary bucket, with a lifecycle rule transitioning objects to STANDARD_IA after 30 days. This bucket does not need its own server access logging because it is itself a log destination.\n5. Do not alter the existing DynamoDB table resource.'
        },
      ],
    });
  }

  protected evaluate(adapter: Ddb002Adapter): ControlFinding | null {
    if (adapter.hasTrailCapturingDynamoDbDataEvents()) {
      return null;
    }
    return {
      scenario: 'no-trail-captures-dynamodb-data-events',
      issue:
        'DynamoDB table data plane events are not captured by any CloudTrail trail in the template',
    };
  }
}

export const ddb002Control = new Ddb002Control();
