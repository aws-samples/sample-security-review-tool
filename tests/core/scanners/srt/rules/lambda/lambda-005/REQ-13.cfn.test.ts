import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-13 (LAMBDA-005): a standalone AWS::IAM::Policy bound to the assessed Lambda
 * execution role via its Roles list must be resolved and evaluated as if the grant
 * were embedded in the role itself.
 *
 * Fixtures are written post-`parseCfnTemplate`: `!Ref ExecRole` has already collapsed
 * to the logical ID string "ExecRole".
 */

const factory = new Lambda005CfnAdapterFactory();

function buildTemplate(policyDocument: unknown): Template {
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
        },
      },
      StandalonePolicy: {
        Type: 'AWS::IAM::Policy',
        Properties: {
          PolicyName: 'exec-role-permissions',
          Roles: ['ExecRole'],
          PolicyDocument: policyDocument,
        },
      },
      ProcessorFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Role: 'ExecRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function contextFor(template: Template, logicalId: string): CfnContext {
  const resources = (template.Resources ?? {}) as Record<string, Resource>;
  return {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId]!,
    logicalId,
  };
}

function run(template: Template, logicalId: string) {
  const context = contextFor(template, logicalId);
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

const WILDCARD_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: '*',
      Resource: '*',
    },
  ],
};

const SCOPED_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: ['s3:GetObject'],
      Resource: ['arn:aws:s3:::app-bucket/*'],
    },
  ],
};

describe('LAMBDA-005 REQ-13 (CloudFormation): standalone IAM policy bound to the Lambda execution role', () => {
  it('flags the execution role when a separately declared AWS::IAM::Policy bound to it allows all actions on all resources', () => {
    const result = run(buildTemplate(WILDCARD_DOCUMENT), 'ExecRole');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('ExecRole');
    expect(result?.resourceType).toBe('AWS::IAM::Role');
  });

  // Opposite outcome: the binding is identical, only the grant is narrowed.
  it('does not flag the execution role when the separately declared policy bound to it grants only specific actions and resource ARNs', () => {
    const result = run(buildTemplate(SCOPED_DOCUMENT), 'ExecRole');

    expect(result).toBeNull();
  });
});
