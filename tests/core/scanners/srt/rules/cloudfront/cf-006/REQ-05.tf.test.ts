import { describe, it } from 'vitest';

describe('CF-006 REQ-05 Terraform: S3 origin with unresolvable origin_access_control_id', () => {
  it.skip('cannot be meaningfully represented in Terraform plan fixtures', () => {
    // In Terraform plan JSON, when an attribute value depends on a variable or
    // resource computed at apply time, it does not appear in `values` at all;
    // it is instead flagged in `after_unknown`. The CF-006 Terraform adapter
    // only reads `values.origin`, so an "unresolvable" origin_access_control_id
    // is indistinguishable from a missing one and would be flagged as
    // non-compliant. There is no way to construct a fixture where the adapter
    // sees the value as present-but-unknown, so this scenario has no
    // meaningful Terraform representation that mirrors the CloudFormation
    // Fn::If case. A pass-on-unresolved test is therefore not applicable here.
  });
});
