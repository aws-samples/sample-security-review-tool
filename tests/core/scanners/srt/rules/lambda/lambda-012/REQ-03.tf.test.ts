import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-03 (Terraform): Lambda function with no execution role configured', () => {
  it('should pass when an aws_lambda_function has no role attribute', () => {
    const lambdaResource = {
      address: 'aws_lambda_function.my_function',
      type: 'aws_lambda_function',
      name: 'my_function',
      values: {
        function_name: 'my-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        // No role attribute at all
      },
    } as unknown as TerraformResource;

    const factory = new Lambda012TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources: [lambdaResource],
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('should pass when one Lambda has no role even if another sibling Lambda has a role', () => {
    const functionWithoutRole = {
      address: 'aws_lambda_function.no_role',
      type: 'aws_lambda_function',
      name: 'no_role',
      values: {
        function_name: 'no-role-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
      },
    } as unknown as TerraformResource;

    const functionWithRole = {
      address: 'aws_lambda_function.with_role',
      type: 'aws_lambda_function',
      name: 'with_role',
      values: {
        function_name: 'with-role-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: 'arn:aws:iam::123456789012:role/some-role',
      },
    } as unknown as TerraformResource;

    const factory = new Lambda012TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: functionWithoutRole,
      allResources: [functionWithoutRole, functionWithRole],
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('should pass when role is explicitly null/undefined in values', () => {
    const lambdaResource = {
      address: 'aws_lambda_function.null_role',
      type: 'aws_lambda_function',
      name: 'null_role',
      values: {
        function_name: 'null-role-function',
        runtime: 'nodejs20.x',
        handler: 'index.handler',
        role: null,
      },
    } as unknown as TerraformResource;

    const factory = new Lambda012TfAdapterFactory();
    const context: TfContext = {
      projectName: 'test-project',
      resource: lambdaResource,
      allResources: [lambdaResource],
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
