import { describe, it } from 'vitest';

describe('CF-001 Terraform - REQ-08: Unresolvable minimum protocol version', () => {
  // Terraform plan output (the data model consumed by the adapter via
  // ctx.resource.values) contains fully-resolved concrete values. There is no
  // representation in the planned-values data model for an "unresolvable
  // condition" analogous to a CloudFormation Fn::If — by the time the plan is
  // produced, conditional/dynamic expressions have already been evaluated to
  // concrete strings (or are simply absent). Therefore this scenario has no
  // meaningful representation in the Terraform format and the test is skipped.
  it.skip('not applicable to Terraform: planned values are always resolved', () => {
    // intentionally skipped
  });
});
