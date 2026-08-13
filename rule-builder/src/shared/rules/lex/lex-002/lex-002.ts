import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CfnBot } from 'aws-cdk-lib/aws-lex';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';

/**
 * Fixture stack for LEX-002.
 *
 * LEX-002 checks that Amazon Lex V2 bot slots have value obfuscation enabled
 * (i.e. ObfuscationSetting.ObfuscationSettingType is NOT "None"). There is a
 * single remediation scenario: "obfuscation-disabled".
 *
 * There is no L2 construct for Amazon Lex bots, so the L1 CfnBot construct is
 * used directly.
 */
export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const botRole = new Role(this, 'LexBotRole', {
      assumedBy: new ServicePrincipal('lexv2.amazonaws.com'),
    });

    new CfnBot(this, 'NonCompliantLexBot', {
      name: 'fixture-lex-002-bot',
      dataPrivacy: {
        ChildDirected: false,
      },
      idleSessionTtlInSeconds: 300,
      roleArn: botRole.roleArn,
      autoBuildBotLocales: false,
      botLocales: [
        {
          localeId: 'en_US',
          nluConfidenceThreshold: 0.4,
          intents: [
            {
              name: 'OrderFlowers',
              sampleUtterances: [{ utterance: 'I would like to order flowers' }],
              slots: [
                // Scenario: obfuscation-disabled
                // ObfuscationSetting explicitly set to "None" -- slot values are
                // NOT masked in conversation logs.
                {
                  name: 'FlowerType',
                  slotTypeName: 'AMAZON.AlphaNumeric',
                  valueElicitationSetting: {
                    slotConstraint: 'Required',
                    promptSpecification: {
                      messageGroupsList: [
                        {
                          message: {
                            plainTextMessage: {
                              value: 'What type of flowers would you like to order?',
                            },
                          },
                        },
                      ],
                      maxRetries: 2,
                    },
                  },
                  obfuscationSetting: {
                    obfuscationSettingType: 'None',
                  },
                },
                // Scenario: obfuscation-disabled
                // ObfuscationSetting omitted entirely -- treated the same as
                // "None" per the adapter (undefined/null => disabled).
                {
                  name: 'CustomerPhoneNumber',
                  slotTypeName: 'AMAZON.PhoneNumber',
                  valueElicitationSetting: {
                    slotConstraint: 'Required',
                    promptSpecification: {
                      messageGroupsList: [
                        {
                          message: {
                            plainTextMessage: {
                              value: 'What phone number should we use to reach you?',
                            },
                          },
                        },
                      ],
                      maxRetries: 2,
                    },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
  }
}
