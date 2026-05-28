import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { Ddb002Adapter } from './ddb-002.adapter.js';
import { s3001Control } from '../../s3/s3-001/s3-001.control.js';
import { s3008Control } from '../../s3/s3-008/s3-008.control.js';

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
            'Add a CloudTrail trail to the template that captures DynamoDB data plane (item-level) events for the offending DynamoDB table. The trail must be actively logging and must include a data event selector whose data resources cover this specific table (or all DynamoDB tables). Do NOT modify the DynamoDB table resource itself — the fix is to introduce CloudTrail (and its supporting resources) into the same template.'
        },
      ],
    
      relatedRules: [s3001Control, s3008Control],
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
