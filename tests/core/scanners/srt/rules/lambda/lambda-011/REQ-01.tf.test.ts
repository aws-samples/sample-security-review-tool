import { describe, it, expect } from 'vitest';
import { lambda011Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.control.js';
import { Lambda011TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-011/lambda-011.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-011 / REQ-01 / Terraform', () => {
  it('flags an aws_lambda_function when no aws_cloudwatch_metric_alarm resources exist anywhere in the project', () => {
    const lambdaResource: TerraformResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      provider_name: 'registry.terraform.io/hashicorp/aws',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/lambda-role',
      },
    } as unknown as TerraformResource;

    const allResources: TerraformResource[] = [lambdaResource];

    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources,
    };

    const factory = new Lambda011TfAdapterFactory();
    expect(factory.appliesTo('aws_lambda_function')).toBe(true);

    const adapter = factory.bind(context);
    const result = lambda011Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LAMBDA-011');
    expect(result!.status).toBe('Open');
    expect(result!.resourceType).toBe('aws_lambda_function');
    expect(result!.resourceName).toBe('aws_lambda_function.my_function');
    expect(result!.priority).toBe('HIGH');
    expect(result!.path).toBe('test-project');
  });
});
