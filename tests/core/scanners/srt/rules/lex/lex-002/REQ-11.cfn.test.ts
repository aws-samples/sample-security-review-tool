import { describe, expect, it } from 'vitest';
import { lex002Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.control.js';
import { Lex002CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-002/lex-002.adapter.cfn.js';
import { CfnContext, Resource, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

/**
 * REQ-11 (LEX-002): A conversational bot has obfuscation disabled on a slot while
 * conversation logging for the bot is not enabled / is explicitly turned off.
 * Expected: flag — obfuscation is a per-slot design-time protection and logging can be
 * enabled independently at the alias level at any time.
 */

const factory = new Lex002CfnAdapterFactory();

interface BotOptions {
  readonly obfuscationSetting?: unknown;
  readonly conversationLogSettings?: unknown;
}

function buildBot(options: BotOptions): Resource {
  const slot: Record<string, unknown> = { Name: 'CardNumber', SlotTypeName: 'AMAZON.Number' };
  if (options.obfuscationSetting !== undefined) slot['ObfuscationSetting'] = options.obfuscationSetting;

  const aliasSettings: Record<string, unknown> = { BotAliasLocaleSettings: [] };
  if (options.conversationLogSettings !== undefined) {
    aliasSettings['ConversationLogSettings'] = options.conversationLogSettings;
  }

  return {
    Type: 'AWS::Lex::Bot',
    Properties: {
      Name: 'PaymentBot',
      RoleArn: 'arn:aws:iam::123456789012:role/lex-role',
      DataPrivacy: { ChildDirected: false },
      IdleSessionTTLInSeconds: 300,
      TestBotAliasSettings: aliasSettings,
      BotLocales: [
        {
          LocaleId: 'en_US',
          NluConfidenceThreshold: 0.4,
          Intents: [{ Name: 'TakePayment', Slots: [slot] }],
        },
      ],
    },
  } as unknown as Resource;
}

function runControl(bot: Resource) {
  const template = { Resources: { PaymentBot: bot } } as unknown as Template;
  const context: CfnContext = {
    stackName: 'lex-stack',
    template,
    resource: bot,
    logicalId: 'PaymentBot',
  };
  return lex002Control.run(factory.bind(context), context);
}

describe('LEX-002 REQ-11 (CloudFormation): slot obfuscation disabled while bot logging is off', () => {
  it('flags a slot with ObfuscationSettingType "None" when no conversation logging is configured', () => {
    const result = runControl(buildBot({ obfuscationSetting: { ObfuscationSettingType: 'None' } }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.resourceType).toBe('AWS::Lex::Bot');
    expect(result?.resourceName).toBe('PaymentBot');
    expect(result?.issue).toContain('CardNumber');
  });

  it('flags a slot with ObfuscationSettingType "None" when conversation logging is explicitly turned off', () => {
    const result = runControl(buildBot({
      obfuscationSetting: { ObfuscationSettingType: 'None' },
      conversationLogSettings: {
        TextLogSettings: [
          {
            Enabled: false,
            Destination: {
              CloudWatch: {
                CloudWatchLogGroupArn: 'arn:aws:logs:us-east-1:123456789012:log-group:/lex/payment',
                LogPrefix: 'payment/',
              },
            },
          },
        ],
      },
    }));

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-002');
    expect(result?.issue).toContain('CardNumber');
  });

  // Opposite outcome: the only thing that changes is the slot's obfuscation type.
  // Logging is still off, so the verdict must flip purely on the slot setting.
  it('does not flag when the same logging-off bot has obfuscation enabled on the slot', () => {
    const result = runControl(buildBot({ obfuscationSetting: { ObfuscationSettingType: 'DefaultObfuscation' } }));

    expect(result).toBeNull();
  });
});
