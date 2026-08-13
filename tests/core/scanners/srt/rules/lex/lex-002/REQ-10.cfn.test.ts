import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import { DEFAULT_OBFUSCATION, NONE_OBFUSCATION } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.js';
import type { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002CfnAdapterFactory();

function makeBot(slots: Record<string, unknown>[]): Resource {
  return {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'SupportBot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      BotLocales: [
        {
          LocaleId: 'en_US',
          NluConfidenceThreshold: 0.4,
          Intents: [
            {
              Name: 'CollectPayment',
              Slots: slots,
            },
          ],
        },
      ],
    },
  } as unknown as Resource;
}

function run(resource: Resource): ScanResult | null {
  const template = { Resources: { SupportBot: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'SupportBot',
  };
  return lex002Control.run(factory.bind(context), context);
}

const obfuscatedSlot = {
  Name: 'CardNumber',
  SlotTypeName: 'AMAZON.Number',
  ObfuscationSetting: { ObfuscationSettingType: DEFAULT_OBFUSCATION },
  ValueElicitationSetting: { SlotConstraint: 'Required' },
};

const unobfuscatedSlot = {
  Name: 'SecurityCode',
  SlotTypeName: 'AMAZON.Number',
  ObfuscationSetting: { ObfuscationSettingType: NONE_OBFUSCATION },
  ValueElicitationSetting: { SlotConstraint: 'Required' },
};

describe('LEX-002 REQ-10 (CloudFormation): obfuscation on a sibling slot does not cover the assessed slot', () => {
  // Primary behavior owned by this requirement: a sibling slot's obfuscation must not excuse an unobfuscated slot.
  it('flags the bot when one slot is obfuscated but another slot leaves values unobfuscated', () => {
    const result = run(makeBot([obfuscatedSlot, unobfuscatedSlot]));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.issue).toContain('SecurityCode');
    expect(result?.issue).not.toContain('CardNumber');
  });

  it('flags the bot when the unobfuscated slot lives in a different intent from the obfuscated slot', () => {
    const resource = {
      Type: 'AWS::Lex::Bot',
      Properties: {
        Name: 'SupportBot',
        BotLocales: [
          {
            LocaleId: 'en_US',
            Intents: [
              { Name: 'CollectPayment', Slots: [obfuscatedSlot] },
              { Name: 'VerifyIdentity', Slots: [unobfuscatedSlot] },
            ],
          },
        ],
      },
    } as unknown as Resource;

    const result = run(resource);

    expect(result).not.toBeNull();
    expect(result?.issue).toContain('SecurityCode');
  });

  // Opposite outcome: same shape, but the assessed slot itself is obfuscated.
  it('does not flag when every slot on the bot has obfuscation enabled', () => {
    const bothObfuscated = {
      ...unobfuscatedSlot,
      ObfuscationSetting: { ObfuscationSettingType: DEFAULT_OBFUSCATION },
    };

    const result = run(makeBot([obfuscatedSlot, bothObfuscated]));

    expect(result).toBeNull();
  });
});
