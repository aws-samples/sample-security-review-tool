import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-17 (LAMBDA-005): when the presence or content of an administrator-level grant on a
 * Lambda execution role cannot be resolved at analysis time, the rule must not report a finding.
 * The wildcard/broad-policy detection behaviour itself is owned by the primary LAMBDA-005
 * requirements; here it only serves as the opposite (resolvable) case.
 */

const factory = new Lambda005CfnAdapterFactory();

function buildTemplate(roleProperties: Record<string, unknown>, extra: Record<string, Resource> = {}): Template {
  return {
    Resources: {
      LambdaRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: {
            Version: '2012-10-17',
            Statement: [
              { Effect: 'Allow', Principal: { Service: 'lambda.amazonaws.com' }, Action: 'sts:AssumeRole' },
            ],
          },
          ...roleProperties,
        },
      } as unknown as Resource,
      MyFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          // !GetAtt LambdaRole.Arn resolves to the logical id after preprocessing
          Role: 'LambdaRole',
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      } as unknown as Resource,
      ...extra,
    },
  } as unknown as Template;
}

function run(template: Template): ScanResult | null {
  const resources = template.Resources as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['LambdaRole'] as Resource,
    logicalId: 'LambdaRole',
  };
  const adapter = factory.bind(context);
  return lambda005Control.run(adapter as never, context);
}

describe('LAMBDA-005 REQ-17 (CloudFormation): undecidable admin-level grants are not flagged', () => {
  it('returns no finding when the attached managed policy arn is an unresolved Fn::If', () => {
    const template = buildTemplate({
      ManagedPolicyArns: [
        { 'Fn::If': ['GrantAdmin', 'arn:aws:iam::aws:policy/AdministratorAccess', 'arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'] },
      ],
    });

    expect(run(template)).toBeNull();
  });

  it('returns no finding when the attached managed policy arn comes from an unresolved Fn::ImportValue', () => {
    const template = buildTemplate({
      ManagedPolicyArns: [{ 'Fn::ImportValue': 'SharedExecutionPolicyArn' }],
    });

    expect(run(template)).toBeNull();
  });

  it('returns no finding when the inline policy document itself is an unresolved Fn::If', () => {
    const template = buildTemplate({
      Policies: [
        {
          PolicyName: 'inline',
          PolicyDocument: {
            'Fn::If': [
              'GrantAdmin',
              { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: '*', Resource: '*' }] },
              { Version: '2012-10-17', Statement: [{ Effect: 'Allow', Action: 'logs:PutLogEvents', Resource: 'arn:aws:logs:us-east-1:123456789012:*' }] },
            ],
          },
        },
      ],
    });

    expect(run(template)).toBeNull();
  });

  // Opposite outcome: the same broad grant, but resolvable at analysis time, must be flagged.
  it('reports a finding when the same administrator-level policy arn is a resolved literal', () => {
    const template = buildTemplate({
      ManagedPolicyArns: ['arn:aws:iam::aws:policy/AdministratorAccess'],
    });

    const result = run(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('LambdaRole');
  });
});
