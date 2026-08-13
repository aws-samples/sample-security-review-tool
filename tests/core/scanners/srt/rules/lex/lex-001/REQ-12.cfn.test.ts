import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'ChildBot';
const STACK_NAME = 'lex-001-stack';

function buildContext(dataPrivacy: unknown): CfnContext {
  const resource = {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'kids-bot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
      IdleSessionTTLInSeconds: 300,
      DataPrivacy: dataPrivacy,
    },
  } as unknown as Resource;

  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;

  return { stackName: STACK_NAME, template, resource, logicalId: LOGICAL_ID };
}

function run(dataPrivacy: unknown) {
  const context = buildContext(dataPrivacy);
  const adapter = new Lex001CfnAdapterFactory().bind(context);
  return lex001Control.run(adapter, context);
}

describe('LEX-001 CloudFormation — conflicting data privacy declarations (REQ-12)', () => {
  // Primary behavior owned by this requirement: conflicting declarations must be flagged.
  it('flags a bot declaring two data privacy configurations where one sets ChildDirected to false', () => {
    const result = run([{ ChildDirected: true }, { ChildDirected: false }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe(LOGICAL_ID);
  });

  it('flags a bot declaring two data privacy configurations where one sets ChildDirected to the string "false"', () => {
    const result = run([{ ChildDirected: 'true' }, { ChildDirected: 'false' }]);

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  // Opposite outcome: nearest input that flips the verdict — every declaration is child-directed true.
  it('does not flag a bot whose multiple data privacy configurations all set ChildDirected to true', () => {
    const result = run([{ ChildDirected: true }, { ChildDirected: true }]);

    expect(result).toBeNull();
  });
});
