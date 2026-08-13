import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'ChildBot';

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
}

function bot(properties: Record<string, unknown>): Resource {
  return { Type: 'AWS::Lex::Bot', Properties: properties } as unknown as Resource;
}

function run(resource: Resource): ScanResult | null {
  const context = buildContext(resource);
  const adapter = new Lex001CfnAdapterFactory().bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 REQ-02 (CloudFormation): DataPrivacy child-directed explicitly true', () => {
  it('applies to AWS::Lex::Bot', () => {
    expect(new Lex001CfnAdapterFactory().appliesTo('AWS::Lex::Bot')).toBe(true);
  });

  // Primary behavior owned by this requirement: explicit true is compliant.
  it('passes when DataPrivacy.ChildDirected is boolean true', () => {
    const result = run(bot({
      Name: 'child-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: { ChildDirected: true },
    }));

    expect(result).toBeNull();
  });

  it('passes when DataPrivacy.ChildDirected is the string "true"', () => {
    const result = run(bot({
      Name: 'child-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: { ChildDirected: 'true' },
    }));

    expect(result).toBeNull();
  });

  // Opposite outcome: the setting is present but declares a non-compliant value.
  it('flags when DataPrivacy.ChildDirected is explicitly false', () => {
    const result = run(bot({
      Name: 'child-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: { ChildDirected: false },
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
  });
});
