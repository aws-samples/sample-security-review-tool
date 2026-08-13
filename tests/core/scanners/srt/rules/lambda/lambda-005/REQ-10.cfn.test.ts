import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-10 (LAMBDA-005): A Lambda execution role attached to a service-wide
 * full-access predefined managed policy (e.g. AmazonS3FullAccess) must be flagged,
 * because such a policy grants every action of that service over all of its
 * resources — more than the specific actions/resources the function requires.
 */

const factory = new Lambda005CfnAdapterFactory();

function buildTemplate(managedPolicyArn: string): Template {
  return {
    Resources: {
      FnRole: {
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
          ManagedPolicyArns: [managedPolicyArn],
        },
      },
      Fn: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          // !GetAtt FnRole.Arn resolves to the logical id after preprocessing
          Role: 'FnRole',
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function runOnRole(template: Template) {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources['FnRole'],
    logicalId: 'FnRole',
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-10 (CloudFormation)', () => {
  it('flags a Lambda execution role attached to a service-wide full-access managed policy', () => {
    const result = runOnRole(buildTemplate('arn:aws:iam::aws:policy/AmazonS3FullAccess'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('FnRole');
    expect(result?.resourceType).toBe('AWS::IAM::Role');
  });

  // Opposite outcome: identical role, but the attached predefined policy is narrowly
  // scoped rather than a service-wide full-access set.
  it('does not flag a Lambda execution role attached to a narrowly scoped managed policy', () => {
    const result = runOnRole(
      buildTemplate('arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole')
    );

    expect(result).toBeNull();
  });
});
