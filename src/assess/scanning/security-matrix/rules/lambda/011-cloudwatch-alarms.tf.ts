import { BaseTerraformRule, TerraformResource } from '../../terraform-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class TfLambda011Rule extends BaseTerraformRule {
  constructor() {
    super(
      'LAMBDA-011',
      'HIGH',
      'Lambda function lacks CloudWatch alarms for monitoring',
      ['aws_lambda_function']
    );
  }

  public evaluate(resource: TerraformResource, projectName: string, allResources: TerraformResource[]): ScanResult | null {
    if (resource.type !== 'aws_lambda_function') return null;

    const functionName = resource.values?.function_name || resource.name;
    const hasAlarms = this.findLambdaAlarms(functionName, allResources);

    if (hasAlarms) return null;

    return this.createScanResult(
      resource,
      projectName,
      this.description,
      'Create CloudWatch alarms for Lambda metrics: Errors, Throttles, Duration, Invocations, ConcurrentExecutions, DeadLetterErrors.'
    );
  }

  private findLambdaAlarms(functionName: string, allResources: TerraformResource[]): boolean {
    return allResources.some(r => {
      if (r.type !== 'aws_cloudwatch_metric_alarm') return false;

      if (r.values?.namespace !== 'AWS/Lambda') return false;

      const dimensions = r.values?.dimensions;
      if (!dimensions || typeof dimensions !== 'object') return false;

      return dimensions.FunctionName === functionName;
    });
  }
}

export default new TfLambda011Rule();
