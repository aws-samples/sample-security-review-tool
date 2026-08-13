import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'ConversationalBot';

/**
 * REQ-08 (LEX-002): obfuscation type is statically 'None' while an unrelated slot
 * attribute is an unresolvable Fn::If. The finding is certain, so the rule must flag.
 */
function buildBot(obfuscationType: string): Resource {
  return {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'support-bot',
      BotLocales: [
        {
          LocaleId: 'en_US',
          Intents: [
            {
              Name: 'CollectPii',
              Slots: [
                {
                  Name: 'SocialSecurityNumber',
                  SlotTypeName: 'AMAZON.Number',
                  // Unrelated attribute depends on an unresolvable condition.
                  Description: { 'Fn::If': ['IsProd', 'prod slot', 'dev slot'] },
                  MultipleValuesSetting: { 'Fn::If': ['IsProd', true, false] },
                  ObfuscationSetting: { ObfuscationSettingType: obfuscationType },
                },
              ],
            },
          ],
        },
      ],
    },
  } as unknown as Resource;
}

function buildContext(resource: Resource): CfnContext {
  const template = { Resources: { [LOGICAL_ID]: resource } } as unknown as Template;
  return { stackName: 'test-stack', template, resource, logicalId: LOGICAL_ID };
}

function run(resource: Resource) {
  const context = buildContext(resource);
  const adapter = new Lex002CfnAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 REQ-08 (CloudFormation)', () => {
  it('flags a slot with obfuscation fixed to None even though an unrelated attribute is unresolvable', () => {
    const result = run(buildBot('None'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.issue).toContain('SocialSecurityNumber');
  });

  // Opposite outcome: same fixture, only the obfuscation type flips to the enabled value.
  it('does not flag when obfuscation is DefaultObfuscation despite the same unresolvable attribute', () => {
    const result = run(buildBot(DEFAULT_OBFUSCATION));

    expect(result).toBeNull();
  });
});
