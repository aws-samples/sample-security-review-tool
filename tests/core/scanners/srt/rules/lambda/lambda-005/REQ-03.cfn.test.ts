import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005CfnAdapterFactory();

function buildTemplate(resourceScope: unknown): Template {
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
          Policies: [
            {
              PolicyName: 'inline-grant',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: '*',
                    Resource: resourceScope,
                  },
                ],
              },
            },
          ],
        },
      },
      Handler: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'handler',
          Runtime: 'nodejs20.x',
          Handler: 'index.handler',
          // !GetAtt ExecRole.Arn resolves to the logical id string 'ExecRole'
          Role: 'ExecRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function run(template: Template, logicalId: string): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId]!,
    logicalId,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (CloudFormation) — wildcard action scoped to a named resource', () => {
  // Primary behaviour owned by this requirement: a wildcard action alone is not a violation.
  it('does not flag a Lambda execution role whose all-actions grant targets a specific named resource ARN', () => {
    const template = buildTemplate('arn:aws:s3:::specific-app-bucket/*');

    expect(run(template, 'ExecRole')).toBeNull();
  });

  it('does not flag when the all-actions grant lists only specific named resource ARNs', () => {
    const template = buildTemplate([
      'arn:aws:dynamodb:us-east-1:123456789012:table/orders',
      'arn:aws:sqs:us-east-1:123456789012:order-queue',
    ]);

    expect(run(template, 'ExecRole')).toBeNull();
  });

  // Opposite case: the nearest input that flips the verdict — resource scope widened to '*'.
  it('flags the same role when the all-actions grant is widened to all resources', () => {
    const template = buildTemplate('*');

    const result = run(template, 'ExecRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('ExecRole');
  });
});
