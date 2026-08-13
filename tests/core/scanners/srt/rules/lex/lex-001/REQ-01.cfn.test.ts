import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001CfnAdapterFactory();

function buildContext(resource: Resource, logicalId = 'MyLexBot'): CfnContext {
  const template = { Resources: { [logicalId]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId };
}

function run(resource: Resource, logicalId = 'MyLexBot'): ScanResult | null {
  const context = buildContext(resource, logicalId);
  const adapter = factory.bind(context);
  return lex001Control.run(adapter, context);
}

describe('LEX-001 (CloudFormation) - DataPrivacy child-directed must be explicitly true', () => {
  // Primary behavior owned by this requirement: no data privacy configuration at all => flag.
  it('flags an AWS::Lex::Bot defined without any DataPrivacy configuration', () => {
    const resource = {
      Type: 'AWS::Lex::Bot',
      Properties: {
        Name: 'order-bot',
        RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
        IdleSessionTTLInSeconds: 300,
      },
    } as unknown as Resource;

    const result = run(resource);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe('MyLexBot');
  });

  // Opposite outcome: same bot, but the child-directed declaration is present and true => no finding.
  it('does not flag an AWS::Lex::Bot whose DataPrivacy ChildDirected is explicitly true', () => {
    const resource = {
      Type: 'AWS::Lex::Bot',
      Properties: {
        Name: 'order-bot',
        RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
        IdleSessionTTLInSeconds: 300,
        DataPrivacy: { ChildDirected: true },
      },
    } as unknown as Resource;

    expect(run(resource)).toBeNull();
  });
});
