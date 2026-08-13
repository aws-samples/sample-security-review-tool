import { Stack, StackProps } from 'aws-cdk-lib';
import { Construct } from 'constructs';
import { CfnBot } from 'aws-cdk-lib/aws-lex';
import { Role, ServicePrincipal } from 'aws-cdk-lib/aws-iam';

export class FixtureStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const botRole = new Role(this, 'LexBotRole', {
      assumedBy: new ServicePrincipal('lexv2.amazonaws.com'),
    });

    // Scenario: MISSING_DATA_PRIVACY
    // CDK's CfnBotProps requires `dataPrivacy` to be supplied at construction time
    // (TypeScript would reject omitting it), so we build the bot with a placeholder
    // value and then use the addPropertyDeletionOverride escape hatch to remove the
    // DataPrivacy property from the synthesized template entirely. This is not a
    // type-cast workaround -- it's the standard CDK mechanism for producing a
    // template that lacks a property the L1 construct otherwise mandates.
    const botMissingDataPrivacy = new CfnBot(this, 'BotMissingDataPrivacy', {
      name: 'MissingDataPrivacyBot',
      roleArn: botRole.roleArn,
      idleSessionTtlInSeconds: 300,
      dataPrivacy: {
        childDirected: true,
      },
    });
    botMissingDataPrivacy.addPropertyDeletionOverride('DataPrivacy');

    // Scenario: CHILD_DIRECTED_NOT_TRUE
    new CfnBot(this, 'BotChildDirectedNotTrue', {
      name: 'ChildDirectedNotTrueBot',
      roleArn: botRole.roleArn,
      idleSessionTtlInSeconds: 300,
      dataPrivacy: {
        childDirected: false,
      },
    });
  }
}
