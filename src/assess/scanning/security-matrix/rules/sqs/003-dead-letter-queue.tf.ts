import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfSqs003Rule extends BaseTerraformRule {
  constructor() {
    super('SQS-003', 'HIGH', 'SQS queue does not have a dead-letter queue configured to handle unprocessable messages', ['aws_sqs_queue']);
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type === 'aws_sqs_queue') {
      const redrivePolicy = resource.values?.redrive_policy;
      if (!redrivePolicy) {
        return this.createScanResult(resource, projectName, this.description, 'Add redrive_policy with deadLetterTargetArn and maxReceiveCount = 3.');
      }
    }

    return null;
  }
}

export default new TfSqs003Rule();
