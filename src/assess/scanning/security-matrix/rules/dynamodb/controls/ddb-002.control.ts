import { SecurityControl } from '../../../controls/security-control.js';
import { ControlFinding } from '../../../controls/types.js';
import { DynamodbAdapter } from '../adapters/dynamodb-adapter.js';

export class Ddb002Control extends SecurityControl<DynamodbAdapter> {
  constructor() {
    super({
      id: 'DDB-002',
      priority: 'HIGH',
      description: 'DynamoDB data plane events must be captured by CloudTrail logging',
      remediationScenarios: [
        {
          scenario: 'missing-data-plane-coverage',
          intent: 'Ensure a CloudTrail trail in the template captures DynamoDB data plane events for the assessed table. The trail must be configured to log data events for the AWS::DynamoDB::Table resource type and must include this specific table (or all DynamoDB tables) in its scope. Do NOT rely on management-events-only configurations, as those do not capture data plane activity.',
        },
      ],
    });
  }

  protected evaluate(adapter: DynamodbAdapter): ControlFinding | null {
    if (this.lacksDataPlaneCoverage(adapter)) {
      return {
        scenario: 'missing-data-plane-coverage',
        issue: 'DynamoDB table data plane events are not captured by any CloudTrail trail in the template',
      };
    }
    return null;
  }

  private lacksDataPlaneCoverage(adapter: DynamodbAdapter): boolean {
    return !adapter.hasDataPlaneCoverage();
  }
}

export const ddb002Control = new Ddb002Control();
