import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Template, Resource, ScanResult } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (LAMBDA-005): A Lambda execution role permission grant that covers every
 * resource (`Resource: "*"`) must be flagged even when the action list is a small set
 * of explicitly named actions — resource scoping is an independent requirement.
 */

const factory = new Lambda005CfnAdapterFactory();

function runControl(template: Template, logicalId: string): ScanResult | null {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId]!,
    logicalId,
  };
  return lambda005Control.run(factory.bind(context), context);
}

function templateWithRoleResource(resource: unknown): Template {
  return {
    Resources: {
      FunctionRole: {
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
              PolicyName: 'FunctionPermissions',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [
                  {
                    Effect: 'Allow',
                    Action: ['s3:GetObject', 's3:PutObject'],
                    Resource: resource,
                  },
                ],
              },
            },
          ],
        },
      },
      MyFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          // !GetAtt FunctionRole.Arn collapses to the logical id after preprocessing
          Role: 'FunctionRole',
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

describe('LAMBDA-005 REQ-05 (CloudFormation): named actions on all resources', () => {
  it('flags an execution role whose inline policy grants named actions on Resource "*"', () => {
    const result = runControl(templateWithRoleResource('*'), 'FunctionRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('FunctionRole');
  });

  // Opposite outcome: same named actions, but the resource scope is a specific ARN.
  it('does not flag the same named actions when scoped to a specific resource ARN', () => {
    const result = runControl(
      templateWithRoleResource('arn:aws:s3:::my-app-bucket/*'),
      'FunctionRole',
    );

    expect(result).toBeNull();
  });
});
