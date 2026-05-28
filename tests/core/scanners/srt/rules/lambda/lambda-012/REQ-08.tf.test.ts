import { describe, it } from 'vitest';

describe('LAMBDA-012 REQ-08 (Terraform): two lambdas with unresolvable execution role references', () => {
  // Terraform plan JSON resolves references during planning. The `values.role` field on
  // an `aws_lambda_function` is either a concrete string ARN (resolved) or absent
  // (unknown after apply). There is no Terraform equivalent of CloudFormation's
  // unresolved intrinsics like Fn::If or Fn::ImportValue that would surface in the plan
  // as an opaque, comparable-but-unresolvable token. The "two unresolvable references
  // that may or may not refer to the same value" scenario therefore has no meaningful
  // representation in the Terraform data model consumed by this adapter.
  it.skip('not applicable: Terraform plan does not produce comparable unresolvable role references', () => {
    // Intentionally skipped — see comment above.
  });
});
