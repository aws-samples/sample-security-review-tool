import { describe, it } from 'vitest';

describe('APIGW-006 (CloudFormation) — catch-all method settings supplied by a separate resource', () => {
  // CloudFormation has no separate "logging settings" resource type that attaches
  // method settings to an existing stage: AWS::ApiGateway::Stage declares its own
  // MethodSettings inline, and the rule only assesses AWS::ApiGateway::Stage.
  // There is therefore no CloudFormation fixture that represents "a separate
  // logging-settings resource explicitly references the assessed stage" without
  // inventing a resource type that does not exist. The scenario is covered by the
  // Terraform test (aws_api_gateway_method_settings) instead.
  it.skip('has no CloudFormation representation: method settings are inline on the stage resource', () => {
    // intentionally empty
  });
});
