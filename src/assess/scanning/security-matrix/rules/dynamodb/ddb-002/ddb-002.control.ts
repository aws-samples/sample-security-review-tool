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
            'Add a CloudTrail trail to the template that captures DynamoDB data plane (item-level) events for the offending DynamoDB table. The trail must be actively logging and must include a data event selector whose data resources cover this specific table (or all DynamoDB tables). Do NOT modify the DynamoDB table resource itself — the fix is to introduce CloudTrail (and its supporting resources) into the same template.\n\nWhen introducing supporting resources, ensure that any S3 bucket created to store CloudTrail logs (or any other S3 bucket added as part of this fix) includes a lifecycle policy/rule that transitions objects to the STANDARD_IA storage class after 30 days. This applies to every new S3 bucket introduced by the remediation, so they do not trigger the "S3 bucket lacks lifecycle policy" rule.\n\nSummary of required additions:\n1. A CloudTrail trail resource that is enabled/actively logging.\n2. A data event selector on the trail covering the specific DynamoDB table (or all DynamoDB tables) for item-level events.\n3. Any S3 bucket introduced to support the trail must have a lifecycle configuration containing at least one rule that transitions objects to STANDARD_IA after 30 days.\n4. Do not alter the existing DynamoDB table resource.'
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
