import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda004Rule extends BaseTerraformRule {
  constructor() {
    super(
      'LAMBDA-004',
      'HIGH',
      'No X-Ray tracing configured for Lambda function',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const tracingConfig = resource.values?.tracing_config;
    if (!tracingConfig || !Array.isArray(tracingConfig) || tracingConfig.length === 0) {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Add a tracing_config block with mode = "Active" to enable X-Ray tracing for the Lambda function.'
      );
    }

    const mode = tracingConfig[0]?.mode;
    if (mode !== 'Active') {
      return this.createScanResult(
        resource,
        projectName,
        this.description,
        'Set tracing_config mode to "Active" to enable X-Ray tracing for the Lambda function.'
      );
    }

    return null;
  }
}

export default new TfLambda004Rule();
