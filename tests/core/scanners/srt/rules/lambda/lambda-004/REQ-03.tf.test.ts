import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (Terraform):
 * Scenario: Lambda function has tracing configuration with mode set to PassThrough.
 * Expected behavior: flag.
 * Rationale: PassThrough mode only propagates tracing context to downstream services
 * and does not cause Lambda itself to record trace segments. This does not satisfy
 * the requirement that X-Ray tracing be enabled for the function.
 */
describe('LAMBDA-004 / REQ-03 / Terraform: PassThrough tracing mode should be flagged', () => {
  const factory = new Lambda004TfAdapterFactory();

  it('flags aws_lambda_function when tracing_config.mode is PassThrough', () => {
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      mode: 'managed',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      schema_version: 0,
      values: {
        function_name: 'my-function',
        runtime: 'nodejs18.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        tracing_config: [
          {
            mode: 'PassThrough',
          },
        ],
      },
    } as unknown as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-004');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.resourceName).toBe('aws_lambda_function.my_function');
    expect(result?.status).toBe('Open');
  });
});
