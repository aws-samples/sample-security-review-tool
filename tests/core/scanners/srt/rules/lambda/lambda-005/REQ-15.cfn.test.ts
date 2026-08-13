import { describe, expect, it } from 'vitest';
import { lambda005Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.control.js';
import { Lambda005CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.cfn.js';
import type { Lambda005Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-005/lambda-005.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lambda005CfnAdapterFactory();

const WILDCARD_POLICY_DOCUMENT = {
  Version: '2012-10-17',
  Statement: [
    {
      Effect: 'Allow',
      Action: '*',
      Resource: '*',
    },
  ],
};

/** Role granting all actions on all resources, trusted only by EC2 (a non-serverless-compute principal). */
function ec2TrustedWildcardRole() {
  return {
    Type: 'AWS::IAM::Role',
    Properties: {
      AssumeRolePolicyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Effect: 'Allow',
            Principal: { Service: 'ec2.amazonaws.com' },
            Action: 'sts:AssumeRole',
          },
        ],
      },
      Policies: [
        {
          PolicyName: 'everything',
          PolicyDocument: WILDCARD_POLICY_DOCUMENT,
        },
      ],
    },
  };
}

function buildContext(template: Template, logicalId: string): CfnContext {
  const resources = (template.Resources ?? {}) as Record<string, any>;
  return {
    stackName: 'test-stack',
    template,
    resource: resources[logicalId],
    logicalId,
  };
}

function runControl(template: Template, logicalId: string) {
  const context = buildContext(template, logicalId);
  const adapter = factory.bind(context) as Lambda005Adapter;
  return lambda005Control.run(adapter, context);
}

describe('LAMBDA-005 (CloudFormation) — REQ-15: wildcard role outside serverless-function scope', () => {
  it('passes a wildcard-granting role that is trusted by EC2 and not used as any function execution role', () => {
    const template = {
      Resources: {
        WildcardRole: ec2TrustedWildcardRole(),
        // Compute in the template is an EC2 instance, not a serverless function.
        AppInstance: {
          Type: 'AWS::EC2::Instance',
          Properties: { ImageId: 'ami-12345', InstanceType: 't3.micro' },
        },
      },
    } as unknown as Template;

    expect(runControl(template, 'WildcardRole')).toBeNull();
  });

  // Opposite outcome: the primary wildcard-grant behavior of LAMBDA-005 owns this case.
  it('flags the identical wildcard-granting role once a serverless function uses it as its execution role', () => {
    const template = {
      Resources: {
        WildcardRole: ec2TrustedWildcardRole(),
        // !GetAtt WildcardRole.Arn resolves to the logical id string after preprocessing.
        AppFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            Role: 'WildcardRole',
            Runtime: 'nodejs20.x',
            Handler: 'index.handler',
            Code: { ZipFile: 'exports.handler = () => {};' },
          },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'WildcardRole');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-005');
    expect(result?.resourceName).toBe('WildcardRole');
  });

  // Lambda cannot assume a role unless its trust policy names lambda.amazonaws.com, so the trust
  // policy puts a role in scope on its own — no function need appear in the template.
  it('flags a wildcard-granting role trusted by Lambda even when no function references it', () => {
    const role = ec2TrustedWildcardRole();
    role.Properties.AssumeRolePolicyDocument.Statement[0].Principal.Service = 'lambda.amazonaws.com';

    const template = {
      Resources: { WildcardRole: role },
    } as unknown as Template;

    const result = runControl(template, 'WildcardRole');
    expect(result).not.toBeNull();
    expect(result?.resourceName).toBe('WildcardRole');
  });

  it('flags a wildcard-granting role used by a SAM serverless function', () => {
    const template = {
      Resources: {
        WildcardRole: ec2TrustedWildcardRole(),
        AppFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: { Role: 'WildcardRole', Runtime: 'nodejs20.x', Handler: 'index.handler' },
        },
      },
    } as unknown as Template;

    const result = runControl(template, 'WildcardRole');
    expect(result).not.toBeNull();
    expect(result?.resourceName).toBe('WildcardRole');
  });
});
