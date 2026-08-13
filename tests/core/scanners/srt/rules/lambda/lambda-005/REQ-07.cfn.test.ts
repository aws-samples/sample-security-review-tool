import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-07 (LAMBDA-005): a Lambda execution role that grants "everything except a
 * short list of excluded actions" (NotAction) on every resource ("*") is an
 * over-broad grant and must be flagged.
 */

const factory = new Lambda005CfnAdapterFactory();

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

function buildTemplate(policyDocument: unknown): Template {
  return {
    Resources: {
      FunctionRole: {
        Type: 'AWS::IAM::Role',
        Properties: {
          AssumeRolePolicyDocument: ASSUME_ROLE_POLICY,
          Policies: [
            {
              PolicyName: 'function-permissions',
              PolicyDocument: policyDocument,
            },
          ],
        },
      },
      ProcessorFunction: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          // !GetAtt FunctionRole.Arn resolves to the logical id string.
          Role: 'FunctionRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
    },
  } as unknown as Template;
}

function runControl(template: Template, logicalId = 'FunctionRole') {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId],
    logicalId,
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-07 (CloudFormation): NotAction grant on all resources', () => {
  it('flags an execution role whose inline policy allows all actions except a few, on all resources', () => {
    const template = buildTemplate({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotAction: ['iam:*', 'organizations:*', 'account:*'],
          Resource: '*',
        },
      ],
    });

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('FunctionRole');
  });

  it('flags the same NotAction grant when the resource wildcard is given as a single-element list', () => {
    const template = buildTemplate({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotAction: 'iam:*',
          Resource: ['*'],
        },
      ],
    });

    const result = runControl(template);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
  });

  // Opposite outcome: the same "all actions except a few" grant, but scoped to
  // specific resource ARNs instead of every resource. The wildcard-resource
  // pairing this requirement turns on is absent, so no finding is expected.
  it('does not flag a NotAction grant that is limited to specific resource ARNs', () => {
    const template = buildTemplate({
      Version: '2012-10-17',
      Statement: [
        {
          Effect: 'Allow',
          NotAction: ['iam:*', 'organizations:*', 'account:*'],
          Resource: [
            'arn:aws:s3:::app-data-bucket',
            'arn:aws:s3:::app-data-bucket/*',
          ],
        },
      ],
    });

    const result = runControl(template);

    expect(result).toBeNull();
  });
});
