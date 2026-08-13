import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-08 (owner of the primary behavior): when the child-directed setting is chosen by an
// unresolvable selection (e.g. Fn::If, which CloudFormation preprocessing leaves as an opaque
// object), but EVERY reachable branch of that selection yields a value that is not true,
// the bot is non-compliant no matter how the condition resolves, so the rule must flag it.

const factory = new Lex001CfnAdapterFactory();

function scan(childDirected: unknown): ScanResult | null {
  const resource = {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'child-bot',
      RoleArn: 'BotRole',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: { ChildDirected: childDirected },
    },
  } as unknown as Resource;

  const template = { Resources: { ChildBot: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ChildBot',
  };

  return lex001Control.run(factory.bind(context), context);
}

describe('LEX-001 CloudFormation - unresolvable selection where all branches are non-true', () => {
  it('flags a bot whose ChildDirected is an Fn::If with false in both branches', () => {
    const result = scan({ 'Fn::If': ['IsProd', false, false] });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe('ChildBot');
  });

  it('flags a bot whose Fn::If branches are non-true values of mixed types', () => {
    const result = scan({ 'Fn::If': ['IsProd', 'false', 'no'] });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  // Opposite outcome: same unresolvable selection mechanism, but one reachable branch yields
  // true, so compliance cannot be ruled out and the rule must stay silent.
  it('does not flag when a reachable branch of the same Fn::If yields true', () => {
    const result = scan({ 'Fn::If': ['IsProd', true, false] });

    expect(result).toBeNull();
  });
});
