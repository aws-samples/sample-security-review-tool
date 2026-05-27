import { Stack, StackProps } from 'aws-cdk-lib';
import * as dynamodb from 'aws-cdk-lib/aws-dynamodb';
import { Construct } from 'constructs';

/**
 * Fixture for rule DDB-002: DynamoDB data plane events must be captured by
 * CloudTrail logging.
 *
 * Scenario: `no-trail-captures-dynamodb-data-events`
 *   The control's evaluate() method scans the synthesized template for any
 *   AWS::CloudTrail::Trail resource that has a (regular or advanced) data
 *   event selector covering the assessed DynamoDB table. If no such trail
 *   exists, the finding is emitted.
 *
 *   To trigger this scenario, we synthesize a DynamoDB table with NO
 *   CloudTrail trail anywhere in the stack — the table's data plane events
 *   are therefore not captured by any trail.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // Non-compliant: a DynamoDB table whose data plane (item-level) events
    // are not captured by any CloudTrail trail in the template.
    new dynamodb.TableV2(this, 'UnmonitoredTable', {
      partitionKey: { name: 'pk', type: dynamodb.AttributeType.STRING },
    });
  }
}
