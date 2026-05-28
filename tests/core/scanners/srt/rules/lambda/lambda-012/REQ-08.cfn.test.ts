import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-08 (CFN): two lambdas with unresolvable execution role references', () => {
  it('passes (returns null) because equality between unresolvable references cannot be established', () => {
    // After parseCfnTemplate preprocessing, Fn::If and Fn::ImportValue remain as opaque
    // objects. The adapter only treats string Role values as comparable, so these
    // unresolvable references should not be considered equal -> no sharing violation.
    const template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-a',
            Role: {
              'Fn::If': ['UseSharedRole', 'arn:aws:iam::123456789012:role/SharedRole', 'arn:aws:iam::123456789012:role/RoleA'],
            },
          },
        },
        FunctionB: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-b',
            Role: {
              'Fn::ImportValue': 'SharedExecutionRoleArn',
            },
          },
        },
      },
    } as unknown as Template;

    const factory = new Lambda012CfnAdapterFactory();

    const stackName = 'test-stack';

    const resultA = lambda012Control.run(
      factory.bind({
        stackName,
        template,
        resource: template.Resources!.FunctionA,
        logicalId: 'FunctionA',
      } as CfnContext),
      {
        stackName,
        template,
        resource: template.Resources!.FunctionA,
        logicalId: 'FunctionA',
      } as CfnContext,
    );

    const resultB = lambda012Control.run(
      factory.bind({
        stackName,
        template,
        resource: template.Resources!.FunctionB,
        logicalId: 'FunctionB',
      } as CfnContext),
      {
        stackName,
        template,
        resource: template.Resources!.FunctionB,
        logicalId: 'FunctionB',
      } as CfnContext,
    );

    expect(resultA).toBeNull();
    expect(resultB).toBeNull();
  });
});
