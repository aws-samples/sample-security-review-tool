import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

// REQ-06 (CloudFormation): LEX-001 owns this behavior. A DataPrivacy.ChildDirected value
// that does not resolve to true (e.g. 'yes', 'no', a number, or an empty value) must be flagged.

const factory = new Lex001CfnAdapterFactory();

function buildContext(childDirected: unknown): CfnContext {
  const resource = {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'kids-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: { ChildDirected: childDirected },
    },
  } as unknown as Resource;

  return {
    stackName: 'test-stack',
    template: { Resources: { LexBot: resource } } as unknown as Template,
    resource,
    logicalId: 'LexBot',
  };
}

function run(childDirected: unknown): ScanResult | null {
  const context = buildContext(childDirected);
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 REQ-06 CloudFormation: ChildDirected value that does not resolve to true', () => {
  it("flags a textual value 'yes' that is not a recognized representation of true", () => {
    const result = run('yes');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe('LexBot');
  });

  it("flags a textual value 'no'", () => {
    expect(run('no')).not.toBeNull();
  });

  it('flags a numeric value of 1', () => {
    expect(run(1)).not.toBeNull();
  });

  it('flags a numeric value of 0', () => {
    expect(run(0)).not.toBeNull();
  });

  it('flags an empty string value', () => {
    expect(run('')).not.toBeNull();
  });

  // Opposite outcome: nearest input that flips the verdict — the value resolves to true.
  it('does not flag when the value resolves to true (boolean)', () => {
    expect(run(true)).toBeNull();
  });

  it("does not flag when the value resolves to true (recognized text 'true')", () => {
    expect(run('true')).toBeNull();
  });
});
