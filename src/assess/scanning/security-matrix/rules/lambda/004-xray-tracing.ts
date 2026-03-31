import { BaseRule, CloudFormationResource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';

export class CompLamb004Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-004',
      'HIGH',
      'No X-Ray tracing configured for Lambda function',
      ['AWS::Lambda::Function']
    );
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    if (resource.Type === 'AWS::Lambda::Function') {
      const tracingConfig = resource.Properties?.TracingConfig;

      if (!tracingConfig) {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Add TracingConfig property to the Lambda function configuration. For CloudFormation templates, ensure the Lambda function's exeuction role has the AWSXrayDaemonWriteAccess policy attached.`
        );
      }

      const tracingMode = tracingConfig.Mode;

      if (tracingMode !== 'Active') {
        return this.createScanResult(
          resource,
          stackName,
          `${this.description}`,
          `Set TracingConfig.Mode to 'Active' to enable X-Ray tracing for the Lambda function`
        );
      }
    }

    return null;
  }
}

export default new CompLamb004Rule();
