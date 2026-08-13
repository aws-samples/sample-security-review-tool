import { describe, it } from 'vitest';
import { lex001Control } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.control.js';
import { Lex001TfAdapterFactory } from '../../../../../../../src/assess/scanning/security-matrix/rules/lex/lex-001/lex-001.adapter.tf.js';

// REQ-08: "child-directed setting is selected by an unresolvable condition, but every possible
// branch of that selection yields a non-true value" has no meaningful representation in the
// Terraform data model this rule sees.
//
// In CloudFormation the selection survives preprocessing as an opaque object
// ({ "Fn::If": [cond, branchA, branchB] }), so all reachable branches are still visible and the
// rule can prove that none of them is true. In Terraform, a conditional whose predicate is not
// known at plan time is collapsed by `terraform show -json` / the plan reader into a single
// unknown value: `child_directed` (or `data_privacy[0].child_directed`) is simply `null`, and the
// candidate branches are not retained anywhere the adapter can read. That `null` case is the
// separate "unknown value -> do not flag" requirement, not this one.
//
// Inventing a fixture (e.g. two competing data_privacy blocks, or a literal false) would test a
// different scenario, so no assertion is made here.
describe('LEX-001 Terraform - unresolvable selection where all branches are non-true', () => {
  it.skip('not representable: Terraform plans collapse an unresolvable selection to a single null value, discarding the branches', () => {
    void lex001Control;
    void Lex001TfAdapterFactory;
  });
});
