import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005TfAdapterFactory();

function policyJson(statement: unknown): string {
  return JSON.stringify({ Version: '2012-10-17', Statement: [statement] });
}

function role(statement: unknown): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'lambda_exec',
    address: 'aws_iam_role.lambda_exec',
    values: {
      name: 'lambda-exec-role',
      assume_role_policy: policyJson({
        Effect: 'Allow',
        Principal: { Service: 'lambda.amazonaws.com' },
        Action: 'sts:AssumeRole',
      }),
      inline_policy: [{ name: 'function-permissions', policy: policyJson(statement) }],
    },
  } as unknown as TerraformResource;
}

// Reference form — HCL wrote `role = aws_iam_role.lambda_exec.arn`
const functionByReference = {
  type: 'aws_lambda_function',
  name: 'handler',
  address: 'aws_lambda_function.handler',
  values: {
    function_name: 'handler',
    runtime: 'nodejs20.x',
    handler: 'index.handler',
    role: 'aws_iam_role.lambda_exec',
  },
} as unknown as TerraformResource;

// Literal form — HCL wrote the role name as a string
const functionByLiteralName = {
  type: 'aws_lambda_function',
  name: 'handler_literal',
  address: 'aws_lambda_function.handler_literal',
  values: {
    function_name: 'handler-literal',
    runtime: 'nodejs20.x',
    handler: 'index.handler',
    role: 'lambda-exec-role',
  },
} as unknown as TerraformResource;

function run(resources: TerraformResource[], target: TerraformResource) {
  const context: TfContext = {
    projectName: 'test-project',
    resource: target,
    allResources: resources,
  };
  return lambda005Control.run(factory.bind(context) as any, context);
}

describe('LAMBDA-005 REQ-02 (Terraform): wildcard action paired with wildcard resource on a Lambda execution role', () => {
  it('flags an execution role whose inline policy allows every action on every resource (reference form)', () => {
    const target = role({ Effect: 'Allow', Action: '*', Resource: '*' });

    const result = run([target, functionByReference], target);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.lambda_exec');
    expect(result?.resourceType).toBe('aws_iam_role');
  });

  it('flags the wildcard grant declared in a separate aws_iam_role_policy resource', () => {
    const target = {
      type: 'aws_iam_role',
      name: 'lambda_exec',
      address: 'aws_iam_role.lambda_exec',
      values: { name: 'lambda-exec-role' },
    } as unknown as TerraformResource;
    const rolePolicy = {
      type: 'aws_iam_role_policy',
      name: 'all_access',
      address: 'aws_iam_role_policy.all_access',
      values: {
        name: 'all-access',
        role: 'aws_iam_role.lambda_exec',
        policy: policyJson({ Effect: 'Allow', Action: ['*'], Resource: ['*'] }),
      },
    } as unknown as TerraformResource;

    const result = run([target, rolePolicy, functionByLiteralName], target);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: identical wiring, but the grant is scoped to the specific
  // actions and resource ARNs the function needs (the compliant form of this
  // requirement). Absence of any grant is a different requirement.
  it('does not flag an execution role whose inline policy is scoped to specific actions and resource ARNs', () => {
    const target = role({
      Effect: 'Allow',
      Action: ['s3:GetObject'],
      Resource: ['arn:aws:s3:::my-app-bucket/*'],
    });

    const result = run([target, functionByReference], target);

    expect(result).toBeNull();
  });
});
