import { Stack, StackProps } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';

/**
 * Fixture for DDB-002: DynamoDB data plane events must be captured by CloudTrail.
 *
 * Scenario triggered: 'no-trail-captures-dynamodb-data-events'
 *   - A DynamoDB table is defined in the stack with no CloudTrail trail
 *     present that captures DynamoDB data plane (item-level) events for it.
 *     The control's evaluate() returns this single scenario when no trail
 *     in the template covers the assessed table.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // A plain DynamoDB table — intentionally no CloudTrail trail in this
    // template, so DDB-002 fires for this resource.
    new dynamodb.TableV2(this, 'UncoveredTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
    });
  }
}
