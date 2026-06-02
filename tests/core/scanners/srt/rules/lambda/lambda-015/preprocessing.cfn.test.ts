import { describe, it, expect } from 'vitest';
import { parseCfnTemplate } from '../../../../../../../src/assess/scanning/security-matrix/cfn-utils.js';
import { lambda015Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.control.js';
import { Lambda015CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lambda/lambda-015/lambda-015.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// These tests feed the template through parseCfnTemplate before the adapter sees
// it — the same path the scanner uses in production. CDK synthesizes container
// image URIs as Fn::Join over account/region/URLSuffix tokens, NOT as the literal
// strings the per-requirement unit tests hand the adapter directly. Without the
// Fn::Join collapse in parseCfnTemplate the rule silently misses every CDK-authored
// container Lambda, which is exactly how LAMBDA-015's fixture failed to trigger.

function runControl(template: Template, logicalId: string) {
  const parsed = parseCfnTemplate(template);
  const resource = parsed.Resources![logicalId];
  const factory = new Lambda015CfnAdapterFactory();
  const context: CfnContext = { stackName: 'test-stack', template: parsed, resource, logicalId };
  return lambda015Control.run(factory.bind(context), context);
}

describe('LAMBDA-015 (CloudFormation preprocessing): synthesized CDK ImageUri', () => {
  it('flags a function whose Fn::Join ImageUri resolves to a :latest tag', () => {
    const template: Template = {
      Resources: {
        ExplicitLatestTagFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: {
                'Fn::Join': ['', [
                  { Ref: 'AWS::AccountId' },
                  '.dkr.ecr.',
                  { Ref: 'AWS::Region' },
                  '.',
                  { Ref: 'AWS::URLSuffix' },
                  '/lambda-015-fixture-repo:latest',
                ]],
              },
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const result = runControl(template, 'ExplicitLatestTagFunction');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.status).toBe('Open');
  });

  it('flags a function whose Fn::Join ImageUri resolves to a reference with no tag or digest', () => {
    const template: Template = {
      Resources: {
        NoTagOrDigestFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: {
                'Fn::Join': ['', [
                  { Ref: 'AWS::AccountId' },
                  '.dkr.ecr.',
                  { Ref: 'AWS::Region' },
                  '.amazonaws.com/lambda-015-fixture-repo',
                ]],
              },
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const result = runControl(template, 'NoTagOrDigestFunction');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LAMBDA-015');
    expect(result?.status).toBe('Open');
  });

  it('does not flag a function whose Fn::Join ImageUri resolves to a specific version tag', () => {
    const template: Template = {
      Resources: {
        PinnedFunction: {
          Type: 'AWS::Lambda::Function',
          Properties: {
            PackageType: 'Image',
            Code: {
              ImageUri: {
                'Fn::Join': ['', [
                  { Ref: 'AWS::AccountId' },
                  '.dkr.ecr.',
                  { Ref: 'AWS::Region' },
                  '.amazonaws.com/lambda-015-fixture-repo:v1.2.3',
                ]],
              },
            },
            Role: 'arn:aws:iam::123456789012:role/lambda-role',
          },
        },
      },
    };

    const result = runControl(template, 'PinnedFunction');

    expect(result).toBeNull();
  });
});
