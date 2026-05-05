import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class Ddb002Rule extends BaseRule {
  private readonly fixPrompt = `Enable CloudTrail logging for DynamoDB data plane events for this table. Create a CloudTrail Trail if none exists. Add this table's ARN to an EventSelector with DataResources type 'AWS::DynamoDB::Table' — append to existing values array if one exists, otherwise create a new EventSelector. For CDK: use the L1 escape hatch (trail.node.defaultChild as CfnTrail).eventSelectors as DataResourceType.DYNAMODB_TABLE does not exist.

IMPORTANT - S3 Bucket Logging Requirements:
If creating a new S3 bucket for CloudTrail logs:
1. First check if the template already has an S3 bucket configured as a logging destination (look for buckets referenced in other buckets' LoggingConfiguration.DestinationBucketName)
2. If a logging bucket exists, configure the new CloudTrail bucket's LoggingConfiguration to use it with LoggingPrefix 'cloudtrail-logs/'
3. If no logging bucket exists, create a dedicated server access logging bucket first, then configure the CloudTrail bucket to log to it with LoggingPrefix 'cloudtrail-logs/'`
  
  constructor() {
    super(
      'DDB-002',
      'HIGH',
      'DynamoDB data plane events are not captured by CloudTrail logging',
      ['AWS::DynamoDB::Table', 'AWS::CloudTrail::Trail']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    if (!this.appliesTo(resource.Type) || !resource.Properties) {
      return null;
    }

    // For DynamoDB tables, check if any CloudTrail captures DynamoDB data events
    if (resource.Type === 'AWS::DynamoDB::Table') {
      if (!allResources?.some(res => res.Type === 'AWS::CloudTrail::Trail' && this.hasDynamoDBDataEvents(res))) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          this.fixPrompt
        );
      }
    }

    return null;
  }

  /**
   * Check if a CloudTrail trail has DynamoDB data events configured
   */
  private hasDynamoDBDataEvents(trail: CloudFormationResource): boolean {
    const eventSelectors = trail.Properties?.EventSelectors;

    if (!Array.isArray(eventSelectors)) {
      return false;
    }

    return eventSelectors.some(selector => {
      const dataResources = selector.DataResources;

      if (!Array.isArray(dataResources)) {
        return false;
      }

      return dataResources.some(dataResource => {
        // Must be DynamoDB type
        if (dataResource.Type !== 'AWS::DynamoDB::Table') {
          return false;
        }

        // Must have values (ARNs)
        const values = dataResource.Values;
        if (!Array.isArray(values) || values.length === 0) {
          return false;
        }

        // Any value indicates DynamoDB data events are configured
        // (whether string, !Sub, !Ref, etc.)
        return true;
      });
    });
  }
}

export default new Ddb002Rule();