import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import type { ChildDirectedSetting, Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-03 (CloudFormation) — owns the "explicit false" behavior of LEX-001:
 * a bot whose DataPrivacy block sets ChildDirected to false is configured-but-disabled
 * and MUST be flagged.
 */

const LOGICAL_ID = 'ChildBot';

function buildTemplate(childDirected: boolean): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::Lex::Bot',
        Properties: {
          Name: 'child-bot',
          RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
          IdleSessionTTLInSeconds: 300,
          DataPrivacy: {
            ChildDirected: childDirected,
          },
        },
      },
    },
  } as unknown as Template;
}

function buildContext(childDirected: boolean): CfnContext {
  const template = buildTemplate(childDirected);
  return {
    stackName: 'lex-stack',
    template,
    resource: template.Resources![LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
}

function buildAdapter(childDirected: ChildDirectedSetting): Lex001Adapter {
  return {
    resourceId: LOGICAL_ID,
    resourceType: 'AWS::Lex::Bot',
    childDirected: () => childDirected,
  };
}

describe('LEX-001 REQ-03 (CloudFormation)', () => {
  it('flags a bot whose DataPrivacy ChildDirected setting is explicitly false', () => {
    const result = lex001Control.run(buildAdapter(false), buildContext(false));

    expect(result).not.toBeNull();
    expect(result!.check_id).toBe('LEX-001');
    expect(result!.resourceType).toBe('AWS::Lex::Bot');
    expect(result!.resourceName).toBe(LOGICAL_ID);
  });

  // Opposite outcome: nearest input that flips the verdict — same DataPrivacy block,
  // ChildDirected present but true.
  it('does not flag a bot whose DataPrivacy ChildDirected setting is explicitly true', () => {
    const result = lex001Control.run(buildAdapter(true), buildContext(true));

    expect(result).toBeNull();
  });
});
