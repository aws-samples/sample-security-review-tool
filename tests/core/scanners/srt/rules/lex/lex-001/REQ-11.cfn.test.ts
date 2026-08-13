import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001CfnAdapterFactory();

function bot(properties: Record<string, unknown>): Resource {
  return {
    Type: 'AWS::Lex::Bot',
    Properties: properties,
  } as unknown as Resource;
}

function templateWith(assessed: Resource, sibling: Resource): Template {
  return {
    Resources: {
      AssessedBot: assessed,
      SiblingBot: sibling,
    },
  } as unknown as Template;
}

function assess(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources as Record<string, Resource>)[logicalId];
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId,
  };
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

const compliantSibling = bot({
  Name: 'SiblingBot',
  RoleArn: 'SiblingRole',
  IdleSessionTTLInSeconds: 300,
  DataPrivacy: { ChildDirected: true },
});

describe('LEX-001 (CloudFormation) - a compliant sibling bot does not cover the assessed bot', () => {
  // Primary behavior owned by REQ-11: per-resource evaluation.
  it('flags the assessed bot with no DataPrivacy even though a sibling bot sets ChildDirected: true', () => {
    const template = templateWith(
      bot({
        Name: 'AssessedBot',
        RoleArn: 'AssessedRole',
        IdleSessionTTLInSeconds: 300,
      }),
      compliantSibling,
    );

    const result = assess(template, 'AssessedBot');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('AssessedBot');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
  });

  it('does not flag the assessed bot when the assessed bot itself sets ChildDirected: true (opposite outcome)', () => {
    const template = templateWith(
      bot({
        Name: 'AssessedBot',
        RoleArn: 'AssessedRole',
        IdleSessionTTLInSeconds: 300,
        DataPrivacy: { ChildDirected: true },
      }),
      compliantSibling,
    );

    expect(assess(template, 'AssessedBot')).toBeNull();
  });

  it('still flags the sibling-compliant template when evaluating the non-compliant bot with ChildDirected: false', () => {
    const template = templateWith(
      bot({
        Name: 'AssessedBot',
        RoleArn: 'AssessedRole',
        IdleSessionTTLInSeconds: 300,
        DataPrivacy: { ChildDirected: false },
      }),
      compliantSibling,
    );

    expect(assess(template, 'AssessedBot')).not.toBeNull();
  });
});
