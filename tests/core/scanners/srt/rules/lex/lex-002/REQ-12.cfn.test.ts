import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import { CfnContext, Resource, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex002CfnAdapterFactory();

function scan(properties: Record<string, unknown>): ScanResult | null {
  const resource = { Type: 'AWS::Lex::Bot', Properties: properties } as unknown as Resource;
  const template = { Resources: { ConversationalBot: resource } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'test-stack',
    template,
    resource,
    logicalId: 'ConversationalBot',
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 CloudFormation - bots with no slots to evaluate (REQ-12)', () => {
  it('does not report a finding when the bot defines no locales at all', () => {
    const result = scan({
      Name: 'OrderBot',
      RoleArn: 'arn:aws:iam::123456789012:role/LexRole',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
    });

    expect(result).toBeNull();
  });

  it('does not report a finding when locales and intents contain an empty set of slots', () => {
    const result = scan({
      Name: 'OrderBot',
      RoleArn: 'arn:aws:iam::123456789012:role/LexRole',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      BotLocales: [
        {
          LocaleId: 'en_US',
          NluConfidenceThreshold: 0.4,
          Intents: [
            { Name: 'GreetIntent', Slots: [] },
            { Name: 'FallbackIntent' },
          ],
        },
      ],
    });

    expect(result).toBeNull();
  });

  it('does not report a finding when a locale declares intents but no Intents list', () => {
    const result = scan({
      Name: 'OrderBot',
      RoleArn: 'arn:aws:iam::123456789012:role/LexRole',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      BotLocales: [{ LocaleId: 'en_US', NluConfidenceThreshold: 0.4, Intents: [] }],
    });

    expect(result).toBeNull();
  });

  // Opposite outcome: the primary "obfuscation must be enabled" behavior is owned by the
  // main LEX-002 requirement. Included here to prove the no-slots pass above is caused by
  // the absence of slots and not by a control that never reports anything.
  it('reports a finding when the intent does contain a slot with obfuscation disabled', () => {
    const result = scan({
      Name: 'OrderBot',
      RoleArn: 'arn:aws:iam::123456789012:role/LexRole',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      BotLocales: [
        {
          LocaleId: 'en_US',
          NluConfidenceThreshold: 0.4,
          Intents: [
            {
              Name: 'GreetIntent',
              Slots: [
                {
                  Name: 'CardNumber',
                  SlotTypeName: 'AMAZON.Number',
                  ObfuscationSetting: { ObfuscationSettingType: 'None' },
                },
              ],
            },
          ],
        },
      ],
    });

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.issue).toContain('CardNumber');
  });
});
