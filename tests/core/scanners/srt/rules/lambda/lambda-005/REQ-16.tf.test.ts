import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { ScanResult, TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005TfAdapterFactory();

function role(statements: unknown[]): TerraformResource {
  return {
    type: 'aws_iam_role',
    name: 'exec',
    address: 'aws_iam_role.exec',
    values: {
      name: 'lambda-exec-role',
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
        {
          name: 'function-permissions',
          policy: JSON.stringify({ Version: '2012-10-17', Statement: statements }),
        },
      ],
    },
  } as unknown as TerraformResource;
}

// Reference form: HCL wrote `role = aws_iam_role.exec.arn`, collapsed to the address.
const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'handler',
  address: 'aws_lambda_function.handler',
  values: {
    function_name: 'handler',
    role: 'aws_iam_role.exec',
    runtime: 'nodejs20.x',
    handler: 'index.handler',
  },
} as unknown as TerraformResource;

function runRole(statements: unknown[]): ScanResult | null {
  const execRole = role(statements);
  const allResources = [execRole, lambdaFunction];
  const context: TfContext = {
    projectName: 'test-project',
    resource: execRole,
    allResources,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (Terraform) - empty inline policy statement list', () => {
  // Primary behavior owned by this requirement: an inline permission document
  // with an empty Statement list grants nothing, so it must not be flagged.
  it('passes when the Lambda execution role has an inline policy with an empty Statement list', () => {
    expect(runRole([])).toBeNull();
  });

  // Opposite outcome: identical setup except the statement list now grants all
  // actions on all resources - the requirement's violation.
  it('flags when the same inline policy document lists a wildcard action on all resources', () => {
    const result = runRole([{ Effect: 'Allow', Action: '*', Resource: '*' }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.exec');
  });
});
