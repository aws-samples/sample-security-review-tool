import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { DEFAULT_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import type { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002CfnAdapterFactory();

function botWithObfuscationType(obfuscationSettingType: string): Resource {
  return {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'CustomerSupportBot',
      RoleArn: 'arn:aws:iam::123456789012:role/LexRole',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      BotLocales: [
        {
          LocaleId: 'en_US',
          NluConfidenceThreshold: 0.4,
          Intents: [
            {
              Name: 'CollectPayment',
              Slots: [
                {
                  Name: 'CardNumber',
                  SlotTypeName: 'AMAZON.Number',
                  ObfuscationSetting: { ObfuscationSettingType: obfuscationSettingType },
                },
              ],
            },
          ],
        },
      ],
    },
  } as unknown as Resource;
}

function runControl(resource: Resource) {
  const template = { Resources: { LexBot: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'LexBot',
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 CloudFormation - REQ-02: slot value obfuscation explicitly set to none/disabled', () => {
  // Primary behavior owned by REQ-02: explicit opt-out of obfuscation must be flagged.
  it('flags a bot slot whose ObfuscationSettingType is None', () => {
    const result = runControl(botWithObfuscationType('None'));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe('LexBot');
    expect(result?.issue).toContain('CardNumber');
  });

  // Opposite outcome: same fixture, obfuscation type present but meeting the standard.
  it('does not flag a bot slot whose ObfuscationSettingType is DefaultObfuscation', () => {
    const result = runControl(botWithObfuscationType(DEFAULT_OBFUSCATION));

    expect(result).toBeNull();
  });
});
