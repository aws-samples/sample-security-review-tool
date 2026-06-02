import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

function buildContext(logicalId: string, resource: Record<string, unknown>): CfnContext {
  const template: Template = {
    Resources: {
      [logicalId]: resource as never,
    },
  };
  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources![logicalId]!,
    logicalId,
  };
}

const factory = new Lambda015CfnAdapterFactory();

describe('LAMBDA-015 REQ-07 (CFN): tags containing "latest" substring but not exactly "latest" should pass', () => {
  const nonExactLatestTags = ['latest-stable', 'v1-latest', 'mylatest', 'latestish', 'LATEST-rc1', 'pre-Latest'];

  for (const tag of nonExactLatestTags) {
    it(`AWS::Lambda::Function with tag '${tag}' does not flag`, () => {
      const resource = {
        Type: 'AWS::Lambda::Function',
        Properties: {
          PackageType: 'Image',
          Code: {
            ImageUri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:${tag}`,
          },
        },
      };
      const ctx = buildContext('MyFn', resource);
      const adapter = factory.bind(ctx);
      const result = lambda015Control.run(adapter, ctx);
      expect(result).toBeNull();
    });

    it(`AWS::Serverless::Function with tag '${tag}' does not flag`, () => {
      const resource = {
        Type: 'AWS::Serverless::Function',
        Properties: {
          PackageType: 'Image',
          ImageUri: `123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:${tag}`,
        },
      };
      const ctx = buildContext('MySamFn', resource);
      const adapter = factory.bind(ctx);
      const result = lambda015Control.run(adapter, ctx);
      expect(result).toBeNull();
    });
  }
});
