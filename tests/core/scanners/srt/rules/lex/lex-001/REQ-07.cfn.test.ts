import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001CfnAdapterFactory();

function buildContext(childDirected: unknown): CfnContext {
  const resource = {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'kids-bot',
      RoleArn: 'BotRole',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: {
        ChildDirected: childDirected,
      },
    },
  } as unknown as Resource;

  const template = {
    Parameters: {
      ChildDirectedFlag: { Type: 'String' },
    },
    Conditions: {
      IsChildDirected: { 'Fn::Equals': [{ Ref: 'ChildDirectedFlag' }, 'true'] },
    },
    Resources: {
      Bot: resource,
    },
  } as unknown as Template;

  return { stackName: 'test-stack', template, resource, logicalId: 'Bot' };
}

function run(childDirected: unknown) {
  const context = buildContext(childDirected);
  return lex001Control.run(factory.bind(context), context);
}

describe('LEX-001 REQ-07 (CloudFormation): unresolvable child-directed value', () => {
  it('passes when ChildDirected is an unresolved Fn::If that survives preprocessing', () => {
    const result = run({ 'Fn::If': ['IsChildDirected', true, false] });
    expect(result).toBeNull();
  });

  it('passes when ChildDirected is an unresolved Fn::ImportValue from another stack', () => {
    const result = run({ 'Fn::ImportValue': 'shared-child-directed-flag' });
    expect(result).toBeNull();
  });

  // Opposite outcome: primary behavior owned by the "explicitly true" requirement.
  // Nearest input that flips the verdict — the value is present and resolvable, but false.
  it('flags a resolvable ChildDirected value of false', () => {
    const result = run(false);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('Bot');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
  });
});
