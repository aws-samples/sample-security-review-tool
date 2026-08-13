import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001CfnAdapterFactory();

function buildContext(properties: Record<string, unknown>): CfnContext {
  const template = {
    Resources: {
      MyBot: {
        Type: 'AWS::Lex::Bot',
        Properties: properties,
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['MyBot'],
    logicalId: 'MyBot',
  };
}

function scan(properties: Record<string, unknown>) {
  const context = buildContext(properties);
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 REQ-04 (CloudFormation): DataPrivacy present but no child-directed value', () => {
  // Primary behavior owned by this requirement: empty DataPrivacy block => flag.
  it('flags a bot whose DataPrivacy block contains no ChildDirected value', () => {
    const result = scan({
      Name: 'my-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/bot-role',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: {},
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
    expect(result!.resourceType).toBe('AWS::Lex::Bot');
    expect(result!.resourceName).toBe('MyBot');
  });

  it('flags a bot whose DataPrivacy block sets ChildDirected to null (no value declared)', () => {
    const result = scan({
      Name: 'my-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/bot-role',
      DataPrivacy: { ChildDirected: null },
    });

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
  });

  // Opposite outcome: nearest input that flips the verdict — same DataPrivacy block,
  // but with the child-directed value explicitly declared true.
  it('does not flag a bot whose DataPrivacy block declares ChildDirected true', () => {
    const result = scan({
      Name: 'my-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/bot-role',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: { ChildDirected: true },
    });

    expect(result).toBeNull();
  });
});
