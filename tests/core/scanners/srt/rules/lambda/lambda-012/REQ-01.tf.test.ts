import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 / REQ-01 / Terraform: Two Lambda functions sharing the same in-template execution role', () => {
  const sharedRole: TerraformResource = {
    address: 'aws_iam_role.shared',
    type: 'aws_iam_role',
    name: 'shared',
    values: {
      name: 'shared-lambda-role',
      assume_role_policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: 'lambda.amazonaws.com' },
            Action: 'sts:AssumeRole',
          },
        ],
      }),
    },
  } as unknown as TerraformResource;

  const functionA: TerraformResource = {
    address: 'aws_lambda_function.function_a',
    type: 'aws_lambda_function',
    name: 'function_a',
    values: {
      function_name: 'function-a',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      filename: 'function.zip',
      role: 'aws_iam_role.shared.arn',
    },
  } as unknown as TerraformResource;

  const functionB: TerraformResource = {
    address: 'aws_lambda_function.function_b',
    type: 'aws_lambda_function',
    name: 'function_b',
    values: {
      function_name: 'function-b',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      filename: 'function.zip',
      role: 'aws_iam_role.shared.arn',
    },
  } as unknown as TerraformResource;

  const allResources = [sharedRole, functionA, functionB];

  const factory = new Lambda012TfAdapterFactory();

  it('flags function_a because it shares its execution role with function_b', () => {
    const ctx: TfContext = {
      projectName: 'test-project',
      resource: functionA,
      allResources,
    };

    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.function_a');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.status).toBe('Open');
  });

  it('flags function_b because it shares its execution role with function_a', () => {
    const ctx: TfContext = {
      projectName: 'test-project',
      resource: functionB,
      allResources,
    };

    const adapter = factory.bind(ctx);
    const result = lambda012Control.run(adapter, ctx);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-012');
    expect(result?.resourceName).toBe('aws_lambda_function.function_b');
    expect(result?.resourceType).toBe('aws_lambda_function');
    expect(result?.status).toBe('Open');
  });
});
