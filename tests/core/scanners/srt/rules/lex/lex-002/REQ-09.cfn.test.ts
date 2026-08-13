import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const LOGICAL_ID = 'ConversationalBot';

function buildTemplate(obfuscationSettingType: string): Template {
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
                  Name: 'CollectPayment',
                  Slots: [
                    {
                      Name: 'CardNumber',
                      SlotTypeName: 'AMAZON.Number',
                      ObfuscationSetting: {
                        ObfuscationSettingType: obfuscationSettingType,
                      },
                    },
                  ],
                },
              ],
            },
          ],
        },
      } as unknown as Resource,
    },
  } as Template;
}

function run(obfuscationSettingType: string) {
  const template = buildTemplate(obfuscationSettingType);
  const resource = (template.Resources as Record<string, Resource>)[LOGICAL_ID];
  const context: CfnContext = {
    stackName: 'lex-stack',
    template,
    resource,
    logicalId: LOGICAL_ID,
  };
  const adapter = new Lex002CfnAdapterFactory().bind(context);
  return lex002Control.run(adapter, context);
}

describe('LEX-002 CloudFormation - unrecognized non-disabled obfuscation type', () => {
  // Primary behavior owned by REQ-09: an obfuscation type that is neither the
  // none/disabled value nor a value the rule specifically recognizes still
  // instructs Lex V2 to obscure slot values, so it must pass.
  it('passes when the slot uses an unrecognized obfuscation type', () => {
    expect(run('FutureObfuscation')).toBeNull();
  });

  it('passes when the slot uses another unrecognized obfuscation type', () => {
    expect(run('PartialObfuscation')).toBeNull();
  });

  // Opposite outcome: the nearest input that flips the verdict is the
  // none/disabled obfuscation type, which LEX-002 must flag.
  it('flags the slot when the obfuscation type is the none/disabled value', () => {
    const result = run('None');
    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceName).toBe(LOGICAL_ID);
    expect(result?.issue).toContain('CardNumber');
  });
});
