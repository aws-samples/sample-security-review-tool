import { describe, expect, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001CfnAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.cfn.js';
import type { Lex001Adapter } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.js';
import type { CfnContext, ScanResult, Template } from '../../../../../../../src/assess/scanning/security-matrix/controls/types.js';

const factory = new Lex001CfnAdapterFactory();

function run(template: Template, logicalId: string): ScanResult | null {
  const resource = (template.Resources ?? {})[logicalId]!;
  const context: CfnContext = { stackName: 'test-stack', template, resource, logicalId };
  const adapter = factory.bind(context) as Lex001Adapter;
  return lex001Control.run(adapter, context);
}

describe('LEX-001 CloudFormation - child-directed declared only on a related resource', () => {
  // REQ-10 (primary): a declaration on a bot alias does not satisfy the assessed bot.
  it('flags a bot when ChildDirected is declared on a sibling bot alias resource instead', () => {
    const template: Template = {
      Resources: {
        ChildBot: {
          Type: 'AWS::Lex::Bot',
          Properties: {
            Name: 'child-bot',
            RoleArn: 'arn:aws:iam::123456789012:role/lex',
            IdleSessionTTLInSeconds: 300,
          },
        },
        ChildBotAlias: {
          Type: 'AWS::Lex::BotAlias',
          Properties: {
            BotAliasName: 'prod',
            BotId: { Ref: 'ChildBot' },
            DataPrivacy: { ChildDirected: true },
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'ChildBot');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
    expect(result?.resourceName).toBe('ChildBot');
  });

  // REQ-10 (primary): a declaration nested on a locale definition does not satisfy the bot.
  it('flags a bot when ChildDirected is declared only inside a bot locale definition', () => {
    const template: Template = {
      Resources: {
        LocaleBot: {
          Type: 'AWS::Lex::Bot',
          Properties: {
            Name: 'locale-bot',
            RoleArn: 'arn:aws:iam::123456789012:role/lex',
            IdleSessionTTLInSeconds: 300,
            BotLocales: [
              {
                LocaleId: 'en_US',
                NluConfidenceThreshold: 0.4,
                DataPrivacy: { ChildDirected: true },
              },
            ],
          },
        },
      },
    } as unknown as Template;

    const result = run(template, 'LocaleBot');

    expect(result).not.toBeNull();
    expect(result?.check_id).toBe('LEX-001');
  });

  // Opposite outcome: identical bot, but the declaration lives on the bot itself.
  it('does not flag a bot that declares ChildDirected true on the bot resource', () => {
    const template: Template = {
      Resources: {
        ChildBot: {
          Type: 'AWS::Lex::Bot',
          Properties: {
            Name: 'child-bot',
            RoleArn: 'arn:aws:iam::123456789012:role/lex',
            IdleSessionTTLInSeconds: 300,
            DataPrivacy: { ChildDirected: true },
          },
        },
        ChildBotAlias: {
          Type: 'AWS::Lex::BotAlias',
          Properties: {
            BotAliasName: 'prod',
            BotId: { Ref: 'ChildBot' },
            DataPrivacy: { ChildDirected: true },
          },
        },
      },
    } as unknown as Template;

    expect(run(template, 'ChildBot')).toBeNull();
  });
});
