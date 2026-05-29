export const TERRAFORM_PLAN_BEHAVIOR = `Before a rule evaluates a Terraform resource, the project's plan reader builds a unified resource tree from \`terraform show -json\`. Two parts of the plan are merged:

- \`planned_values\` holds resolved literal values for each resource argument. Anything unknown at plan time is omitted (key absent) or recorded as \`null\`.
- \`configuration\` preserves the original expressions, including cross-resource references like \`{ references: ["aws_s3_bucket.x.id", "aws_s3_bucket.x"] }\`.

Understanding what values the rule will actually see is essential for writing correct adapters and tests.

## References Collapse to Resource Addresses

A field whose value is a reference to another resource is collapsed to that resource's **address** (\`aws_<type>.<name>\`). For example, \`bucket = aws_s3_bucket.X.id\` (or \`.bucket\`, or \`.bucket_regional_domain_name\`) becomes the string \`"aws_s3_bucket.X"\` in the resource's \`values\`.

This mirrors CloudFormation preprocessing, where \`!Ref MyBucket\` and \`!GetAtt MyBucket.Arn\` both collapse to the string \`"MyBucket"\`.

### Example

\`\`\`hcl
# main.tf
resource "aws_s3_bucket" "logs" {
  bucket = "my-logs-bucket"
}

resource "aws_s3_bucket_logging" "site" {
  bucket        = aws_s3_bucket.site.id
  target_bucket = aws_s3_bucket.logs.id
}
\`\`\`

After the plan reader has run, the adapter sees:

\`\`\`ts
// aws_s3_bucket_logging.site.values
{
  bucket: "aws_s3_bucket.site",
  target_bucket: "aws_s3_bucket.logs"
}
\`\`\`

A literal bucket name, in contrast, stays as the literal:

\`\`\`hcl
resource "aws_s3_bucket_logging" "site" {
  bucket        = "my-site-bucket"
  target_bucket = "my-logs-bucket"
}
\`\`\`

\`\`\`ts
// aws_s3_bucket_logging.site.values
{ bucket: "my-site-bucket", target_bucket: "my-logs-bucket" }
\`\`\`

## Adapter Idiom for Cross-Resource Lookups

When an adapter needs to know whether resource A's field points at resource B, compare \`A.values.<field>\` against \`B.address\`. Also accept the literal name (\`B.values.bucket\` for S3, \`B.values.name\`, etc.) for the case where users wired the rule by literal string.

\`\`\`ts
private referencesBucket(logging: TerraformResource, bucket: TerraformResource): boolean {
  const target = (logging.values as Record<string, unknown>)?.['target_bucket'];
  if (typeof target !== 'string') return false;
  if (target === bucket.address) return true;
  const literalName = (bucket.values as Record<string, unknown>)?.['bucket'];
  return typeof literalName === 'string' && target === literalName;
}
\`\`\`

Do **not** look for or destructure a \`{ references: [...] }\` object — by the time the adapter sees the resource the reference has already been collapsed to the address string.

## Test Idiom

Hand-built \`TerraformResource.values\` for cross-resource scenarios should set the cross-resource field to the target's address string, not a references object. Cover both the literal and the reference form:

\`\`\`ts
// Literal form — user wrote the bucket name as a string in HCL
const literalLogging: TerraformResource = {
  type: 'aws_s3_bucket_logging',
  name: 'site',
  address: 'aws_s3_bucket_logging.site',
  values: { bucket: 'my-site-bucket', target_bucket: 'my-logs-bucket' },
};

// Reference form — user wrote 'aws_s3_bucket.logs.id' in HCL
const referenceLogging: TerraformResource = {
  type: 'aws_s3_bucket_logging',
  name: 'site',
  address: 'aws_s3_bucket_logging.site',
  values: { bucket: 'aws_s3_bucket.site', target_bucket: 'aws_s3_bucket.logs' },
};
\`\`\`

Any test exercising a SPECIFIC_RESOURCE requirement must include at least one reference-form case so the adapter is exercised against the same shape it will see in production.

## What Stays Unresolved

These cases are NOT collapsed and remain as they were:

- A multi-source interpolation where the field expression references more than one resource (e.g. an \`Fn::Sub\`-equivalent string interpolating multiple resource attributes). The field stays \`null\`.
- Any value the plan reader cannot identify as a single-resource reference.

Adapters that encounter \`null\` for a critical field should treat it as "unknown" (do not flag), the same way CloudFormation rules treat \`Fn::If\` as unknown.

## Summary for Adapter Authors

1. Cross-resource lookups use \`target.address\` (or the literal name) — never a references object.
2. Literal names and addresses are both strings; a single \`typeof === 'string'\` guard with two compares is enough.
3. \`null\` means "unknown" — pass, do not flag.
`;
