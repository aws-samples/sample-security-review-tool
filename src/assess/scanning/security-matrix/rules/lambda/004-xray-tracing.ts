import { BaseRule, CloudFormationResource, Resource } from '../../security-rule-base.js';
import { ScanResult } from '../../../base-scanner.js';
import { Template } from 'cloudform-types';

/**
 * LAMBDA-004: Lambda functions must have AWS X-Ray active tracing enabled.
 *
 * Uses the template-aware evaluateResource entry point to inspect each
 * AWS::Lambda::Function resource individually.
 *
 * Checks:
 * - TracingConfig property is present on the Lambda function.
 * - TracingConfig.Mode is set to 'Active' (not 'PassThrough' or omitted).
 *
 * Known limitations:
 * - Cross-stack references where TracingConfig is set via a nested stack or
 *   imported value cannot be resolved and may produce false positives.
 */
export class CompLamb004Rule extends BaseRule {
  constructor() {
    super(
      'LAMBDA-004',
      'HIGH',
      'No X-Ray tracing configured for Lambda function',
      ['AWS::Lambda::Function']
    );
  }

  public evaluateResource(stackName: string, template: Template, resource: Resource): ScanResult | null {
    if (!this.appliesTo(resource.Type)) return null;

    const tracingConfig = resource.Properties?.TracingConfig;

    if (!tracingConfig) {
      return this.createMissingTracingResult(stackName, template, resource);
    }

    if (tracingConfig.Mode !== 'Active') {
      return this.createInactiveTracingResult(stackName, template, resource, tracingConfig.Mode);
    }

    return null;
  }

  public evaluate(resource: CloudFormationResource, stackName: string): ScanResult | null {
    return null;
  }

  private createMissingTracingResult(stackName: string, template: Template, resource: Resource): ScanResult {
    return this.createResult(
      stackName,
      template,
      resource,
      this.description,
      `Add TracingConfig property to the Lambda function configuration with Mode set to 'Active' to enable AWS X-Ray tracing. This allows distributed tracing of requests through the function. The function's execution role must also have the AWSXrayDaemonWriteAccess managed policy attached. Simply adding TracingConfig without setting Mode to 'Active' will not satisfy this requirement.`
    );
  }

  private createInactiveTracingResult(stackName: string, template: Template, resource: Resource, currentMode: string): ScanResult {
    return this.createResult(
      stackName,
      template,
      resource,
      this.description,
      `Set TracingConfig.Mode to 'Active' to enable X-Ray tracing for the Lambda function. The current value '${currentMode}' does not enable active tracing. Only 'Active' mode samples and records incoming requests. 'PassThrough' mode defers tracing decisions to the upstream caller and does not satisfy this requirement.`
    );
  }
}

export default new CompLamb004Rule();
