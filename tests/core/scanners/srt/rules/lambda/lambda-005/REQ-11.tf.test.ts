import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const ROLE_ADDRESS = 'aws_iam_role.lambda_exec';
const ROLE_NAME = 'processor-exec-role';

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'lambda_exec',
  address: ROLE_ADDRESS,
  values: {
    name: ROLE_NAME,
    assume_role_policy: JSON.stringify({
      Version: '2012-10-17',
      Statement: [
        { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
      ],
    }),
  },
} as unknown as TerraformResource;

const lambdaFunction: TerraformResource = {
  type: 'aws_lambda_function',
  name: 'processor',
  address: 'aws_lambda_function.processor',
  // Reference form: HCL wrote `role = aws_iam_role.lambda_exec.arn`
  values: { function_name: 'processor', handler: 'index.handler', runtime: 'nodejs20.x', role: ROLE_ADDRESS },
} as unknown as TerraformResource;

/** Reference-form attachment: HCL wrote `role = aws_iam_role.lambda_exec.name`. */
function referenceAttachment(name: string, policyArn: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy_attachment',
    name,
    address: `aws_iam_role_policy_attachment.${name}`,
    values: { role: ROLE_ADDRESS, policy_arn: policyArn },
  } as unknown as TerraformResource;
}

/** Literal-form attachment: HCL wrote the role name as a string. */
function literalAttachment(name: string, policyArn: string): TerraformResource {
  return {
    type: 'aws_iam_role_policy_attachment',
    name,
    address: `aws_iam_role_policy_attachment.${name}`,
    values: { role: ROLE_NAME, policy_arn: policyArn },
  } as unknown as TerraformResource;
}

function evaluateRole(attachments: TerraformResource[]) {
  const allResources = [role, lambdaFunction, ...attachments];
  const context: TfContext = { projectName: 'test-project', resource: role, allResources };
  const adapter = new Lambda005TfAdapterFactory().bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (Terraform) — narrowly scoped predefined permission sets', () => {
  // Primary behavior owned by this requirement: a minimal, purpose-built managed policy must not be flagged.
  it('does not flag a Lambda execution role attached only to the minimal log-writing managed policy (reference form)', () => {
    const result = evaluateRole([
      referenceAttachment('logs', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'),
    ]);

    expect(result).toBeNull();
  });

  it('does not flag a Lambda execution role attached only to narrowly scoped managed policies (literal form)', () => {
    const result = evaluateRole([
      literalAttachment('logs', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'),
      literalAttachment('vpc', 'arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole'),
    ]);

    expect(result).toBeNull();
  });

  // Opposite outcome: identical wiring, only the breadth of the predefined permission set changes.
  it('flags the same Lambda execution role when the attached managed policy is administrator-level', () => {
    const result = evaluateRole([
      referenceAttachment('admin', 'arn:aws:iam::aws:policy/AdministratorAccess'),
    ]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe(ROLE_ADDRESS);
  });
});
