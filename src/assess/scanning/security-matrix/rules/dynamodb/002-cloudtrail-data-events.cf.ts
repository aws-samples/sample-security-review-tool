import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * DDB-002: DynamoDB tables must have CloudTrail data plane event logging
 * enabled.
 *
 * For each DynamoDB table, scans all CloudTrail Trail resources in the same
 * template for an EventSelector or AdvancedEventSelector that covers DynamoDB
 * data events.
 *
 * Checks:
 * - At least one trail has a basic EventSelector with a DataResource of type
 *   AWS::DynamoDB::Table and a non-empty Values array.
 * - OR at least one trail has an AdvancedEventSelector whose FieldSelectors
 *   include eventCategory=Data AND resources.type=AWS::DynamoDB::Table.
 *
 * Known limitations:
 * - CloudTrail trails defined in other stacks/templates are not visible — the
 *   rule only inspects resources within the same synthesized template.
 * - Organization-level trails configured outside CloudFormation are not
 *   detected.
 * - The rule does not verify that the EventSelector ARN values match the
 *   specific table — it only confirms that some DynamoDB data event
 *   configuration exists on a trail in the template.
 * - IsLogging is not checked; a trail with IsLogging: false would still
 *   satisfy the rule, though IsLogging is a required CFN property so it must
 *   be explicitly set.
 */
export class Ddb002Rule extends BaseRule {
  private readonly fixPrompt = `Enable CloudTrail logging for DynamoDB data plane events for this table.

Steps:
1. If no CloudTrail Trail exists, create one. It needs an S3 bucket for logs. Create a dedicated access-logging bucket (BlockPublicAccess.BLOCK_ALL, enforceSSL: true), then create the trail bucket with that as its serverAccessLogsBucket (prefix 'cloudtrail-logs/'). If an existing access-logging bucket is already in the template, reuse it.
2. Add an EventSelector to the trail with DataResources containing type 'AWS::DynamoDB::Table' and this table's ARN in Values. Set ReadWriteType to 'All'.

For CDK: The L2 Trail construct does NOT support adding DynamoDB data event selectors directly (no DataResourceType.DYNAMODB_TABLE). You MUST use the L1 escape hatch after creating the trail:
  const cfnTrail = trail.node.defaultChild as cloudtrail.CfnTrail;
  cfnTrail.eventSelectors = [{ dataResources: [{ type: 'AWS::DynamoDB::Table', values: [table.tableArn] }], readWriteType: 'All' }];

IMPORTANT: Do NOT set objectOwnership on S3 buckets — the CDK default handles ACLs correctly for server access logging. Do NOT use trail.logAllS3DataEvents() or similar L2 methods.`
  
  constructor() {
    super(
      'DDB-002',
      'HIGH',
      'DynamoDB data plane events are not captured by CloudTrail logging',
      ['AWS::DynamoDB::Table']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (!this.appliesTo(resource.Type) || !resource.Properties) return null;

    const hasTrailCoverage = Object.entries(template.Resources || {}).some(([_, r]) => r.Type === 'AWS::CloudTrail::Trail' && this.hasDynamoDBDataEvents(r));

    if (!hasTrailCoverage) {
      return this.createResult(stackName, template, resource, this.description, this.fixPrompt);
    }

    return null;
  }

  public evaluate(resource: CloudFormationResource, stackName: string, allResources?: CloudFormationResource[]): ScanResult | null {
    return null;
  }

  /**
   * Check if a CloudTrail trail has DynamoDB data events configured
   * via either basic EventSelectors or AdvancedEventSelectors
   */
  private hasDynamoDBDataEvents(trail: Resource): boolean {
    return this.hasBasicEventSelectorForDynamoDB(trail) || this.hasAdvancedEventSelectorForDynamoDB(trail);
  }

  /**
   * Check basic EventSelectors for DynamoDB data events
   */
  private hasBasicEventSelectorForDynamoDB(trail: Resource): boolean {
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

  /**
   * Check AdvancedEventSelectors for DynamoDB data events.
   * A valid advanced selector for DynamoDB data events must have:
   * - eventCategory Equals "Data"
   * - resources.type Equals "AWS::DynamoDB::Table"
   */
  private hasAdvancedEventSelectorForDynamoDB(trail: Resource): boolean {
    const advancedSelectors = trail.Properties?.AdvancedEventSelectors;

    if (!Array.isArray(advancedSelectors)) {
      return false;
    }

    return advancedSelectors.some(selector => {
      const fieldSelectors = selector.FieldSelectors;

      if (!Array.isArray(fieldSelectors)) {
        return false;
      }

      let hasDataCategory = false;
      let hasDynamoDBResourceType = false;

      for (const field of fieldSelectors) {
        const fieldName = field.Field;
        const equalsValues = field.Equals;

        if (!fieldName || !Array.isArray(equalsValues)) {
          continue;
        }

        if (fieldName === 'eventCategory' && equalsValues.includes('Data')) {
          hasDataCategory = true;
        }

        if (fieldName === 'resources.type' && equalsValues.includes('AWS::DynamoDB::Table')) {
          hasDynamoDBResourceType = true;
        }
      }

      return hasDataCategory && hasDynamoDBResourceType;
    });
  }
}

export default new Ddb002Rule();
