import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.tf.js';
import { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-04 (Terraform): distinct execution roles per Lambda', () => {
  const factory = new Lambda012TfAdapterFactory();

  // Two separately-defined IAM roles with distinct ARNs (distinct identities),
  // even though the attached policy contents are identical.
  const functionA: TerraformResource = {
    address: 'aws_lambda_function.function_a',
    type: 'aws_lambda_function',
    name: 'function_a',
    values: {
      function_name: 'function-a',
      runtime: 'nodejs20.x',
      handler: 'index.handler',
      role: 'arn:aws:iam::123456789012:role/role-a',
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
      role: 'arn:aws:iam::123456789012:role/role-b',
    },
  } as unknown as TerraformResource;

  // Sibling IAM role resources (identity-only semantics: two separate role
  // resources with identical inline policy contents).
  const roleA: TerraformResource = {
    address: 'aws_iam_role.role_a',
    type: 'aws_iam_role',
    name: 'role_a',
    values: {
      name: 'role-a',
      assume_role_policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
        ],
      }),
    },
  } as unknown as TerraformResource;

  const roleB: TerraformResource = {
    address: 'aws_iam_role.role_b',
    type: 'aws_iam_role',
    name: 'role_b',
    values: {
      name: 'role-b',
      assume_role_policy: JSON.stringify({
        Version: '2012-10-17',
        Statement: [
          { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
        ],
      }),
    },
  } as unknown as TerraformResource;

  const allResources: TerraformResource[] = [functionA, functionB, roleA, roleB];

  it('passes for function_a when it has its own distinct execution role identity', () => {
    const ctx: TfContext = {
      projectName: 'test-project',
      resource: functionA,
      allResources,
    };

    const adapter = factory.bind(ctx);
    expect(adapter.sharesExecutionRole).toBe(false);

    const result = lambda012Control.run(adapter, ctx);
    expect(result).toBeNull();
  });

  it('passes for function_b when it has its own distinct execution role identity', () => {
    const ctx: TfContext = {
      projectName: 'test-project',
      resource: functionB,
      allResources,
    };

    const adapter = factory.bind(ctx);
    expect(adapter.sharesExecutionRole).toBe(false);

    const result = lambda012Control.run(adapter, ctx);
    expect(result).toBeNull();
  });
});
