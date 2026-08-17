export const TERRAFORM_SOURCE_BEHAVIOR = `Before a rule evaluates a Terraform resource, \`TerraformSourceReader\` builds the resource list by parsing the project's \`.tf\` files with \`@cdktf/hcl2json\`. It does not run \`terraform\`, and it never reads a plan or a state file. There is no \`terraform show -json\`, no \`planned_values\`, and no \`configuration\` block: the rule sees the source as written, with a narrow set of expressions substituted.

Every \`.tf\` file in the project root is parsed, plus any module directories listed in \`.terraform/modules/modules.json\`. Resources from a downloaded module carry an address prefix (\`module.<key>.\`).

Understanding what values the rule will actually see is essential for writing correct adapters and tests.

## Resource Shape

Each resource arrives as:

\`\`\`ts
{ type: 'aws_autoscaling_group', name: 'a', address: 'aws_autoscaling_group.a', values: { ... } }
\`\`\`

An argument the author did not write is **absent** from \`values\`. No key is ever set to \`null\` to mean unknown.

## Nested Blocks Are Arrays

hcl2json represents every block as an array of objects, even when written once. Repeated blocks each get an entry.

\`\`\`hcl
resource "aws_autoscaling_group" "a" {
  launch_template {
    id = aws_launch_template.lt.id
  }
  tag { key = "one" }
  tag { key = "two" }
}
\`\`\`

\`\`\`ts
// aws_autoscaling_group.a.values
{
  launch_template: [ { id: 'aws_launch_template.lt' } ],
  tag: [ { key: 'one' }, { key: 'two' } ]
}
\`\`\`

Reading \`values.launch_template.id\` yields \`undefined\`. It is \`values.launch_template[0].id\`.

## What Gets Substituted

Only a string that is **entirely** one interpolation is examined. Everything else is passed through as written.

| Written in HCL | What the adapter sees |
|---|---|
| \`default_cooldown = 300\` | \`300\` (number) |
| \`default_cooldown = "300"\` | \`"300"\` (string) |
| \`default_cooldown = var.x\`, \`variable "x" { default = 0 }\` anywhere in the project | \`0\` (number — zero and false survive) |
| \`default_cooldown = var.x\`, no default declared | \`"__unresolved__:var.x"\` |
| \`id = aws_launch_template.lt.id\` | \`"aws_launch_template.lt"\` |
| \`x = local.thing\` | \`"__unresolved__:local.thing"\` |
| \`x = data.aws_ami.chosen.id\` | \`"__unresolved__:data.aws_ami.chosen.id"\` |
| \`x = "prefix-\${var.y}"\` | \`"prefix-\${var.y}"\` verbatim, braces intact |

**Variable defaults are pooled across the project's own files.** A \`variable\` block in \`variables.tf\` does reach a resource in \`main.tf\` — the usual layout — so a \`var.\` reference whose declaration carries a default arrives as that value. Only a variable with no declared default arrives unresolved.

This holds for the files the project itself owns. Inside a module downloaded under \`.terraform/modules\`, a variable is an argument its caller supplies, and the reader does not read what was passed in, so those references stay unresolved rather than standing in for a value that may have been overridden.

**A reference to a resource collapses to its first two segments** — its address, which is what cross-resource matching needs. Anything in a namespace that is not a resource (\`var\`, \`local\`, \`data\`, \`module\`, \`each\`, \`count\`, \`path\`, \`self\`, \`terraform\`) is a value the scanner cannot know, so the reader marks it instead.

## Unknown Values Are Marked, Not Guessed

A value the reader could not work out arrives carrying the \`__unresolved__:\` prefix. Never compare against that prefix by hand — call the shared guard:

\`\`\`ts
import { isUnresolved } from '../../terraform-rule-base.js';

if (isUnresolved(cooldown)) return null;   // configuration unknown, no finding
\`\`\`

\`isUnresolved\` also returns true for a partly interpolated string such as \`"prefix-\${var.y}"\`, which keeps its original text because the literal part can still matter.

Check it **before** judging a value invalid, out of range, or absent from an allowed set. An unknown configuration is not a breach: the scanner cannot assert what it cannot see, exactly as CloudFormation rules treat an unresolved intrinsic. Skipping this guard is the single most common source of false positives in Terraform rules.

## Adapter Idiom For Cross-Resource Lookups

To decide whether resource A's field points at resource B, compare \`A.values.<field>\` against \`B.address\`. Also accept B's literal name, for the case where the author wired it up by string.

\`\`\`ts
private referencesBucket(logging: TerraformResource, bucket: TerraformResource): boolean {
  const target = (logging.values as Record<string, unknown>)?.['target_bucket'];
  if (typeof target !== 'string') return false;
  if (target === bucket.address) return true;
  const literalName = (bucket.values as Record<string, unknown>)?.['bucket'];
  return typeof literalName === 'string' && target === literalName;
}
\`\`\`

Do **not** look for a \`{ references: [...] }\` object. Nothing in this pipeline produces one.

## Test Idiom

Hand-built \`TerraformResource.values\` must match the shapes above: blocks as arrays, references as address strings, unresolved variables as \`"var.x"\` strings.

\`\`\`ts
// Literal form — author typed the value
const literal: TerraformResource = {
  type: 'aws_autoscaling_group', name: 'a', address: 'aws_autoscaling_group.a',
  values: { default_cooldown: 0, launch_template: [{ id: 'aws_launch_template.lt' }] },
};

// Reference form — author wrote var.cooldown with no reachable default
const reference: TerraformResource = {
  type: 'aws_autoscaling_group', name: 'b', address: 'aws_autoscaling_group.b',
  values: { default_cooldown: unresolved('var.cooldown') },
};
\`\`\`

A requirement about a value's magnitude needs a reference-form case as well as a literal one, so the adapter is exercised against the shape it will actually meet.

## Summary

1. Source is parsed directly. No plan, no state, no \`planned_values\`.
2. Blocks are arrays: \`values.block[0].field\`.
3. Variable defaults resolve only within the same \`.tf\` file; \`0\` and \`false\` survive.
4. Guard value checks with \`isUnresolved(value)\` and return no finding when it is true.
5. Cross-resource fields hold the target's address; compare against \`target.address\`.
6. An absent argument is a missing key, never \`null\`.
`;
