import { describe, it } from 'vitest';

describe('AS-003 CloudFormation - notification target group supplied by a deployment-time input', () => {
  // In CloudFormation there is no standalone notification resource that names the Auto
  // Scaling group it applies to: NotificationConfigurations is an inline property of
  // AWS::AutoScaling::AutoScalingGroup, so the group a notification configuration applies
  // to is always the enclosing resource and can never come from a deployment-time input.
  // The scenario therefore has no meaningful CloudFormation fixture, and inventing one
  // (e.g. an unresolved NotificationConfigurations value) would test a different
  // requirement rather than this one.
  it.skip('has no CloudFormation representation: the notification target group is structurally the enclosing resource', () => {
    // intentionally skipped - see comment above
  });
});
