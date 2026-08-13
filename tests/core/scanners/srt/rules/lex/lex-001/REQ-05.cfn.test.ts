import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-05 (LEX-001): A child-directed setting expressed as a truthy textual
 * representation of `true` (e.g. the literal text "true", case-insensitively)
 * conveys the same explicit COPPA declaration as a native boolean `true`
 * and must be treated as compliant.
 */

const factory = new Lex001CfnAdapterFactory();

function buildContext(childDirected: unknown): CfnContext {
  const template = {
    Resources: {
      CoppaBot: {
        Type: 'AWS::Lex::Bot',
        Properties: {
          Name: 'coppa-bot',
          RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
          DataPrivacy: {
            ChildDirected: childDirected,
          },
        },
      },
    },
  } as unknown as Template;

  return {
    stackName: 'test-stack',
    template,
    resource: template.Resources!['CoppaBot'],
    logicalId: 'CoppaBot',
  };
}

function bind(childDirected: unknown): Lex001Adapter {
  return factory.bind(buildContext(childDirected)) as Lex001Adapter;
}

describe('LEX-001 REQ-05 CloudFormation: textual true for DataPrivacy.ChildDirected', () => {
  it.each(['true', 'True', 'TRUE', 'TrUe'])(
    'treats the textual value %s as an explicit child-directed declaration',
    (textualTrue) => {
      const adapter = bind(textualTrue);

      expect(adapter.childDirected()).toBe(true);
      expect(lex001Control.run(adapter, buildContext(textualTrue))).toBeNull();
    },
  );

  // Opposite outcome: the nearest input that flips the verdict — the setting is
  // still present as text, but the text does not represent true.
  // Primary behavior for a false declaration is owned by the "missing/false
  // DataPrivacy" requirement; asserted here only to prove this file discriminates.
  it('flags a textual value of "false" as non-compliant', () => {
    const context = buildContext('false');
    const adapter = factory.bind(context) as Lex001Adapter;

    expect(adapter.childDirected()).toBe(false);

    const result = lex001Control.run(adapter, context);
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('CoppaBot');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
  });
});
