import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-12 (LAMBDA-005): A Lambda execution role attached to a mix of permission sets —
 * several narrowly scoped managed policies plus one administrator- or power-user-level
 * policy — must still be flagged. The presence of well-scoped attachments does not
 * satisfy the rule, because effective privilege is the union of all attachments.
 */

const NARROW_POLICY_ARNS = [
  'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole',
  'arn:aws:iam::aws:policy/AmazonS3ReadOnlyAccess',
];

const NARROW_INLINE_POLICY = {
  PolicyName: 'ReadOneTable',
  PolicyDocument: {
    Version: '2012-10-17',
    Statement: [
      {
        Effect: 'Allow',
        Action: ['dynamodb:GetItem'],
        Resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/Orders',
      },
    ],
  },
};

function buildTemplate(managedPolicyArns: string[]): Template {
  return {
    Resources: {
      ExecRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              {
                Effect: 'Allow',
                Principal: { Service: 'lambda.amazonaws.com' },
                Action: 'sts:AssumeRole',
              },
            ],
          },
          ManagedPolicyArns: managedPolicyArns,
          Policies: [NARROW_INLINE_POLICY],
        },
      },
      OrderProcessor: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'order-processor',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          // !GetAtt ExecRole.Arn resolves to the logical id after preprocessing
          Role: 'ExecRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function runOnRole(template: Template): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, never>;
  const context: CfnContext = {
    stackName: 'lambda-stack',
    template,
    resource: resources['ExecRole'],
    logicalId: 'ExecRole',
  };
  const adapter = new Lambda005CfnAdapterFactory().bind(context);
  return lambda005Control.run(adapter, context);
}

const broadScenarioIntent = lambda005Control.remediationScenarios
  .find(scenario => scenario.scenario === 'overly-broad-managed-policy')?.intent;

describe('LAMBDA-005 REQ-12 (CloudFormation): mixed narrow + admin-level attachments', () => {
  it('flags an execution role whose narrow policies are accompanied by AdministratorAccess', () => {
    const result = runOnRole(buildTemplate([...NARROW_POLICY_ARNS, 'arn:aws:iam::aws:policy/AdministratorAccess']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('ExecRole');
    expect(result?.fix).toBe(broadScenarioIntent);
  });

  it('flags an execution role whose narrow policies are accompanied by PowerUserAccess', () => {
    const result = runOnRole(buildTemplate([...NARROW_POLICY_ARNS, 'arn:aws:iam::aws:policy/PowerUserAccess']));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.fix).toBe(broadScenarioIntent);
  });

  // Opposite outcome: identical fixture except the broad policy is replaced by another
  // narrowly scoped policy, so the union of attachments stays least-privilege.
  it('does not flag when every attached permission set is narrowly scoped', () => {
    const result = runOnRole(buildTemplate([...NARROW_POLICY_ARNS, 'arn:aws:iam::aws:policy/AWSXRayDaemonWriteAccess']));

    expect(result).toBeNull();
  });
});
