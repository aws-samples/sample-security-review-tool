import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { TfContext, TerraformResource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005TfAdapterFactory();

const NARROW_STATEMENTS = [
  {
    Effect: 'Allow',
    Action: ['s3:GetObject', 's3:PutObject'],
    Resource: ['arn:aws:s3:::orders-intake-bucket/*'],
  },
  {
    Effect: 'Allow',
    Action: 'dynamodb:GetItem',
    Resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/Orders',
  },
];

function policyJson(finalStatement: Record<string, unknown>): string {
  return JSON.stringify({
    Version: '2012-10-17',
    Statement: [...NARROW_STATEMENTS, finalStatement],
  });
}

function role(finalStatement: Record<string, unknown>): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'order_processor',
    address: 'aws_iam_role.order_processor',
    values: {
      name: 'order-processor-role',
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
      inline_policy: [
        { name: 'order-processor-permissions', policy: policyJson(finalStatement) },
      ],
    },
  } as unknown as TerraformResource;
}

// Reference form: HCL was `role = aws_iam_role.order_processor.arn`, which the plan
// reader collapses to the role's address string.
const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'order_processor',
  address: 'aws_lambda_function.order_processor',
  values: {
    function_name: 'order-processor',
    role: 'aws_iam_role.order_processor',
    runtime: 'nodejs20.x',
    handler: 'index.handler',
  },
} as unknown as TerraformResource;

function runOnRole(finalStatement: Record<string, unknown>) {
  const roleResource = role(finalStatement);
  const allResources = [roleResource, lambdaFunction];
  const context: TfContext = {
    projectName: 'order-project',
    resource: roleResource,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-08 (Terraform): mixed inline grants on a Lambda execution role', () => {
  // Primary behavior owned by this requirement: permissions are cumulative, so one
  // all-actions/all-resources grant makes the role administrative.
  it('flags the role when one of several inline grants allows every action on every resource', () => {
    const result = runOnRole({ Effect: 'Allow', Action: '*', Resource: '*' });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.order_processor');
    expect(result?.resourceType).toBe('aws_iam_role');
  });

  // Opposite outcome: identical role except the final grant names specific actions
  // and specific resource ARNs rather than wildcards.
  it('does not flag the role when every grant names specific actions and specific resource ARNs', () => {
    const result = runOnRole({
      Effect: 'Allow',
      Action: ['sqs:SendMessage'],
      Resource: ['arn:aws:sqs:us-east-1:123456789012:order-events'],
    });

    expect(result).toBeNull();
  });
});
