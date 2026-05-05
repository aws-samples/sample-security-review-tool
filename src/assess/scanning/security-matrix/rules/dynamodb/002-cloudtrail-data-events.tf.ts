import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfDdb002Rule extends BaseTerraformRule {
  constructor() {
    super(
      'DDB-002',
      'HIGH',
      'DynamoDB data plane events are not captured by CloudTrail logging',
      ['aws_dynamodb_table']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_dynamodb_table') return null;

    const hasCloudTrailWithDynamoDB = allResources.some(r =>
      r.type === 'aws_cloudtrail' && this.hasDynamoDBDataEvents(r)
    );

    if (!hasCloudTrailWithDynamoDB) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Enable CloudTrail logging for DynamoDB data plane events. Create an aws_cloudtrail resource with an event_selector that includes data_resource of type "AWS::DynamoDB::Table".'
      );
    }

    return null;
  }

  private hasDynamoDBDataEvents(trail: TerraformResource): boolean {
    const eventSelectors = trail.values?.event_selector;
    if (!Array.isArray(eventSelectors)) return false;

    return eventSelectors.some((selector: any) => {
      const dataResources = selector.data_resource;
      if (!Array.isArray(dataResources)) return false;

      return dataResources.some((dataResource: any) =>
        dataResource.type === 'AWS::DynamoDB::Table' &&
        Array.isArray(dataResource.values) &&
        dataResource.values.length > 0
      );
    });
  }
}

export default new TfDdb002Rule();
