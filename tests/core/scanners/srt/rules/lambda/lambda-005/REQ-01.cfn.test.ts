import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * LAMBDA-005 / REQ-01
 *
 * Requirement owning the primary behavior asserted here:
 *   A Lambda execution role that grants no permissions at all (no inline policy
 *   documents and no attached managed policies) confers no privileges, so there is
 *   nothing over-broad to report -> the control must PASS (return null).
 *
 * The discriminating (opposite) test at the bottom keeps everything identical except
 * that the very thing the requirement turns on — the presence of a permission grant —
 * is a wildcard-action/wildcard-resource inline policy, which must be FLAGGED.
 */

const ASSUME_ROLE_POLICY = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Principal: { Service: 'lambda.amazonaws.com' },
      Action: 'sts:AssumeRole',
    },
  ],
};

function buildTemplate(rolePropsExtras: Record<string, unknown>): Template {
  return {
    Resources: {
      ExecRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: ASSUME_ROLE_POLICY,
          ...rolePropsExtras,
        },
      },
      MyFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'my-function',
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          // !GetAtt ExecRole.Arn resolves to the logical id string after preprocessing
          Role: 'ExecRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template, logicalId: string): ScanResult | null {
  const factory = new Lambda005CfnAdapterFactory();
  const resource = (template.Resources as Record<string, any>)[logicalId];
  expect(factory.appliesTo(resource.Type)).toBe(true);
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context);
  return lambda005Control.run(adapter as never, context);
}

describe('LAMBDA-005 REQ-01 (CloudFormation): execution role with no permission grants', () => {
  it('passes when the Lambda execution role has neither inline policies nor managed policy attachments', () => {
    const template = buildTemplate({});

    expect(run(template, 'ExecRole')).toBeNull();
  });

  it('passes when the role declares empty permission collections rather than omitting them', () => {
    const template = buildTemplate({ Policies: [], ManagedPolicyArns: [] });

    expect(run(template, 'ExecRole')).toBeNull();
  });

  // OPPOSITE CASE — owned by the wildcard-inline-policy requirement.
  // Identical role, except a permission grant now exists and it is over-broad.
  it('flags the same role when a permission grant exists and uses wildcard action with wildcard resource', () => {
    const template = buildTemplate({
      Policies: [
        {
          PolicyName: 'inline',
          PolicyDocument: {
            Version: '2012-10-17',
            Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }],
          },
        },
      ],
    });

    const result = run(template, 'ExecRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });
});
