import { describe, it, expect } from 'vitest';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-09 (CFN): Lambda function's container image reference is gated by a conditional
 * (Fn::If) where at least one branch yields a 'latest' tag and another branch yields
 * a specific version tag.
 *
 * Expected: flag — any branch that can produce 'latest' is treated as a violation,
 * because that branch can be selected at deploy time and result in a non-pinned
 * deployment.
 *
 * Note: After parseCfnTemplate preprocessing, Fn::If remains as an unresolved object
 * (not a string), so the rule must look inside the conditional branches to detect
 * the 'latest' tag rather than skipping it as "unknown".
 */
describe('LAMBDA-015 REQ-09 CFN: conditional ImageUri with a latest branch', () => {
  const factory = new Lambda015CfnAdapterFactory();

  it('flags AWS::Lambda::Function when Fn::If has one branch yielding :latest and another a specific version', () => {
    const template: Template = {
      Conditions: {
        UseLatest: { 'Fn::Equals': [{ Ref: 'Env' }, 'dev'] },
      },
      Resources: {
        MyFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: {
                'Fn::If': [
                  'UseLatest',
                  '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest',
                  '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:1.2.3',
                ],
              },
            },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['MyFunction']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MyFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceName).toBe('MyFunction');
    expect(result?.resourceType).toBe('AWS::Lambda::Function');
  });

  it('flags AWS::Serverless::Function when Fn::If has one branch yielding :latest and another a specific version', () => {
    const template: Template = {
      Conditions: {
        IsDev: { 'Fn::Equals': [{ Ref: 'Env' }, 'dev'] },
      },
      Resources: {
        MySamFunction: {
          Type: 'AWS::Serverless::Function',
          Properties: {
            PackageType: 'Image',
            ImageUri: {
              'Fn::If': [
                'IsDev',
                '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:2.0.0',
                '123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest',
              ],
            },
          },
        },
      },
    } as unknown as Template;

    const resource = template.Resources!['MySamFunction']!;
    const context: CfnContext = {
      stackName: 'test-stack',
      template,
      resource,
      logicalId: 'MySamFunction',
    };

    const adapter = factory.bind(context);
    const result = lambda015Control.run(adapter, context);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.resourceName).toBe('MySamFunction');
    expect(result?.resourceType).toBe('AWS::Serverless::Function');
  });
});
