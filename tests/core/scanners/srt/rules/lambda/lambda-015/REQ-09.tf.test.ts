import { describe, it } from 'vitest';

/**
 * REQ-09 (Terraform): Lambda function's container image reference is gated by a
 * conditional where at least one branch yields a 'latest' tag and another branch
 * yields a specific version tag.
 *
 * SKIPPED: This scenario does not have a meaningful representation in the Terraform
 * plan data model. Terraform's plan reader resolves conditional expressions
 * (`condition ? a : b`) at plan time:
 *   - If both branches are literal strings, the plan resolves to the single chosen
 *     literal — no conditional structure remains for the rule to inspect.
 *   - If the condition depends on an unknown value, the field is recorded as `null`
 *     (which the adapter treats as "unknown" — pass, do not flag).
 *
 * There is no Terraform construct equivalent to CloudFormation's Fn::If that survives
 * to the rule as an object exposing both branches. The "branch yielding latest vs.
 * branch yielding a specific version" scenario is uniquely expressible in
 * CloudFormation; the CFN test file covers it.
 */
describe.skip('LAMBDA-015 REQ-09 TF: conditional image_uri with a latest branch', () => {
  it('not applicable — see comment above', () => {
    // Intentionally empty.
  });
});
