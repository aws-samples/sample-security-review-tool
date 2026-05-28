import { describe, it, expect } from 'vitest';
import { lambda012Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.control.js';
import { Lambda012CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-012/lambda-012.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

describe('LAMBDA-012 REQ-07 (CloudFormation): unresolvable execution role reference', () => {
  it('passes when the Role property is an unresolved intrinsic (Fn::If) and cannot be compared to siblings', () => {
    // After parseCfnTemplate preprocessing, Fn::If remains as an opaque object.
    // The adapter's getRole only returns strings, so an object Role becomes `undefined`,
    // which short-circuits sharing detection -> pass (no finding).
    const template: Template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-a',
            Role: {
              'Fn::If': ['UseSharedRole', 'SharedRoleArn', 'DedicatedRoleArn'],
            },
          },
        },
        FunctionB: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-b',
            // A concrete sibling role - even if it happened to match one of the
            // Fn::If branches, we cannot know that at analysis time.
            Role: 'SharedRoleArn',
          },
        },
      },
    };

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionA,
      logicalId: 'FunctionA',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });

  it('passes when the Role property is an unresolved Fn::ImportValue', () => {
    // Fn::ImportValue also remains unresolved after preprocessing.
    const template: Template = {
      Resources: {
        FunctionA: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-a',
            Role: { 'Fn::ImportValue': 'SharedRoleArnExport' },
          },
        },
        FunctionB: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            FunctionName: 'function-b',
            Role: { 'Fn::ImportValue': 'SharedRoleArnExport' },
          },
        },
      },
    };

    const factory = new Lambda012CfnAdapterFactory();
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource: template.Resources!.FunctionA,
      logicalId: 'FunctionA',
    };

    const adapter = factory.bind(context);
    const result = lambda012Control.run(adapter, context);

    expect(result).toBeNull();
  });
});
