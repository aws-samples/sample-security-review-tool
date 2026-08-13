import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.tf.js';
import type { TerraformResource, TfContext } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (LAMBDA-005): An execution role used by a Lambda function that is attached to a
 * predefined administrator-level managed policy (full control over the account) must be flagged.
 */

const factory = new Lambda005TfAdapterFactory();

const role: TerraformResource = {
  type: 'aws_iam_role',
  name: 'lambda_exec',
  address: 'aws_iam_role.lambda_exec',
  values: {
    name: 'lambda-exec-role',
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
  // role = aws_iam_role.lambda_exec.arn collapses to the role address
  values: { function_name: 'processor', role: 'aws_iam_role.lambda_exec', runtime: 'nodejs20.x' },
} as unknown as TerraformResource;

const attachment = (roleRef: string, policyArn: string): TerraformResource => ({
  type: 'aws_iam_role_policy_attachment',
  name: 'admin',
  address: 'aws_iam_role_policy_attachment.admin',
  values: { role: roleRef, policy_arn: policyArn },
} as unknown as TerraformResource);

const evaluateRole = (attachmentResource: TerraformResource) => {
  const allResources = [role, lambdaFunction, attachmentResource];
  const context: TfContext = {
    projectName: 'lambda-005-project',
    resource: role,
    allResources,
  };
  return lambda005Control.run(factory.bind(context), context);
};

describe('LAMBDA-005 REQ-09 (Terraform)', () => {
  it('flags a Lambda execution role with an AdministratorAccess attachment (reference form)', () => {
    const result = evaluateRole(
      attachment('aws_iam_role.lambda_exec', 'arn:aws:iam::aws:policy/AdministratorAccess'),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('aws_iam_role.lambda_exec');
    expect(result?.resourceType).toBe('aws_iam_role');
  });

  it('flags a Lambda execution role with an AdministratorAccess attachment (literal role name form)', () => {
    const result = evaluateRole(
      attachment('lambda-exec-role', 'arn:aws:iam::aws:policy/AdministratorAccess'),
    );

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: identical wiring, only the breadth of the attached managed policy changes.
  it('does not flag a Lambda execution role attached to a narrowly scoped managed policy', () => {
    const result = evaluateRole(
      attachment(
        'aws_iam_role.lambda_exec',
        'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
      ),
    );

    expect(result).toBeNull();
  });
});
