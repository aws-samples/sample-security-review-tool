import { describe, it, expect } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { CfnContext, Template, Resource } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005CfnAdapterFactory();

const NARROW_STATEMENTS = [
  {
    Effect: 'Allow',
    Action: ['s3:GetObject', 's3:PutObject'],
    Resource: ['arn:aws:s3:::orders-intake-bucket/*'],
  },
  {
    Effect: 'Allow',
    Action: 'dynamodb:GetItem',
    Resource: 'arn:aws:dynamodb:us-east-1:123456789012:table/Orders',
  },
];

/**
 * Builds a template where a Lambda function uses ExecutionRole, and the role
 * carries several narrow inline grants plus one final grant supplied by the caller.
 * `Role: 'ExecutionRole'` is what !GetAtt ExecutionRole.Arn resolves to after preprocessing.
 */
function buildTemplate(finalStatement: Record<string, unknown>): Template {
  return {
    Resources: {
      OrderProcessor: {
        Type: 'AWS::Lambda::Function',
        Properties: {
          FunctionName: 'order-processor',
          Handler: 'index.handler',
          Runtime: 'nodejs20.x',
          Role: 'ExecutionRole',
          Code: { ZipFile: 'exports.handler = async () => {};' },
        },
      },
      ExecutionRole: {
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
              PolicyName: 'order-processor-permissions',
              PolicyDocument: {
                Version: '2012-10-17',
                Statement: [...NARROW_STATEMENTS, finalStatement],
              },
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function runOnRole(template: Template) {
  const resources = template.Resources as Record<string, Resource>;
  const context: CfnContext = {
    stackName: 'order-stack',
    template,
    resource: resources['ExecutionRole'] as Resource,
    logicalId: 'ExecutionRole',
  };
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 REQ-08 (CloudFormation): mixed inline grants on a Lambda execution role', () => {
  // Primary behavior owned by this requirement: a single all-actions/all-resources grant
  // makes the role administrative regardless of how well-scoped the sibling grants are.
  it('flags the role when one of several grants allows every action on every resource', () => {
    const result = runOnRole(buildTemplate({ Effect: 'Allow', Action: '*', Resource: '*' }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('ExecutionRole');
    expect(result?.resourceType).toBe('AWS::IAM::Role');
  });

  // Opposite outcome: the same role, same number of grants, but the final grant is
  // scoped to specific actions and specific resource ARNs instead of wildcards.
  it('does not flag the role when every grant names specific actions and specific resource ARNs', () => {
    const result = runOnRole(
      buildTemplate({
        Effect: 'Allow',
        Action: ['sqs:SendMessage'],
        Resource: ['arn:aws:sqs:us-east-1:123456789012:order-events'],
      }),
    );

    expect(result).toBeNull();
  });
});
