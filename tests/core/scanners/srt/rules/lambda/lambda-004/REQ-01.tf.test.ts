import { describe, it, expect } from 'vitest';
import { lambda004Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.control.js';
import { Lambda004TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-004/lambda-004.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-004 - Terraform - Lambda function with no tracing configuration', () => {
  it('flags aws_lambda_function when tracing_config block is not specified', () => {
    const resource: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
        filename: 'lambda.zip',
      },
    } as TerraformResource;

    const context: TfContext = {
      projectName: 'test-project',
      resource,
      allResources: [resource],
    };

    const factory = new Lambda004TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda004Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-004');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.resourceName).toBe('aws_lambda_function.my_function');
    expect(result?.status).toBe('Open');
    expect(result?.priority).toBe('HIGH');
  });
});
