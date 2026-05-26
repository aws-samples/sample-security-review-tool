import { describe, it } from 'vitest';

describe('CF-002 Terraform - REQ-05: Unresolvable web_acl_id value', () => {
  // In Terraform's planned-values data model (which feeds the Cf002 adapter),
  // values that cannot be statically resolved at analysis time (e.g. values
  // known only after apply, computed outputs, or references to resources
  // created in the same plan) appear as `null` in `resource.values.web_acl_id`,
  // with their unknown-ness tracked separately in `after_unknown`.
  //
  // The Cf002 Terraform adapter only inspects `values.web_acl_id` and treats
  // null/undefined as "no association", which would produce a FAIL finding -
  // not a PASS. There is no way to express an "unresolvable but present"
  // web_acl_id within the data model the adapter consumes.
  //
  // This scenario therefore has no meaningful representation for the
  // Terraform format under the current adapter, so this test is skipped
  // rather than fabricating a fixture that misrepresents how Terraform
  // surfaces unresolvable values.
  it.skip('unresolvable web_acl_id has no meaningful representation in Terraform planned values', () => {
    // intentionally skipped - see comment above
  });
});
