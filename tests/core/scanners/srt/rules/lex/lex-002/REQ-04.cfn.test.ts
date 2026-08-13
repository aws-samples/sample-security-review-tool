import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const STACK_NAME = 'lex-stack';
const LOGICAL_ID = 'ConversationalBot';

function buildTemplate(obfuscationSetting: unknown): Template {
  return {
    Resources: {
      [LOGICAL_ID]: {
        Type: 'AWS::Lex::Bot',
        Properties: {
          Name: 'support-bot',
          BotLocales: [
            {
              LocaleId: 'en_US',
              Intents: [
                {
                  Name: 'CollectCardIntent',
                  Slots: [
                    {
                      Name: 'CardNumber',
                      SlotTypeName: 'AMAZON.Number',
                      ObfuscationSetting: obfuscationSetting,
                    },
                  ],
                },
              ],
            },
          ],
        },
      },
    },
  } as unknown as Template;
}

function run(obfuscationSetting: unknown): ScanResult | null {
  const template = buildTemplate(obfuscationSetting);
  const context: CfnContext = {
    stackName: STACK_NAME,
    template,
    resource: template.Resources![LOGICAL_ID],
    logicalId: LOGICAL_ID,
  };
  const adapter = new Lex002CfnAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 CloudFormation - REQ-04: obfuscation configuration present without a type value', () => {
  // Primary behavior owned by REQ-04: an ObfuscationSetting block with no
  // ObfuscationSettingType provides no evidence of masking and must be flagged.
  it('flags a slot whose ObfuscationSetting block carries no ObfuscationSettingType', () => {
    const result = run({});

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.issue).toContain('CardNumber');
  });

  it('flags a slot whose ObfuscationSettingType is present but explicitly null', () => {
    const result = run({ ObfuscationSettingType: null });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
  });

  // Opposite outcome: same structure, but the type value is present and selects masking.
  it('does not flag a slot whose ObfuscationSetting block carries DefaultObfuscation', () => {
    const result = run({ ObfuscationSettingType: DEFAULT_OBFUSCATION });

    expect(result).toBeNull();
  });
});
